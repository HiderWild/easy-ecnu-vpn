#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <sddl.h>

#include "platform/common/backend_resolver.hpp"
#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/oneshot_bootstrap.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "observability/log_facade.hpp"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace exv {
namespace platform {
namespace {


bool wait_for_helper_pipe_available(const std::string &endpoint,
                                    DWORD *last_error) {
  for (int i = 0; i < 40; ++i) {
    if (WaitNamedPipeA(endpoint.c_str(), 100)) {
      return true;
    }
    if (last_error) {
      *last_error = GetLastError();
    }
    Sleep(100);
  }
  return false;
}

bool helper_executable_exists(const std::string &helper_path) {
  const DWORD attrs = GetFileAttributesA(helper_path.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES &&
         (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string current_owner_sid() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    return "";

  DWORD needed = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
  if (needed == 0) {
    CloseHandle(token);
    return "";
  }

  std::vector<unsigned char> buffer(needed);
  if (!GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
    CloseHandle(token);
    return "";
  }
  CloseHandle(token);

  auto *user = reinterpret_cast<TOKEN_USER *>(buffer.data());
  LPSTR sid = nullptr;
  if (!ConvertSidToStringSidA(user->User.Sid, &sid))
    return "";
  std::string result = sid;
  LocalFree(sid);
  return result;
}

std::string quote_arg(const std::string &value) {
  if (value.empty())
    return "\"\"";
  bool needs_quotes = value.find_first_of(" \t\"") != std::string::npos;
  if (!needs_quotes)
    return value;

  std::string quoted = "\"";
  unsigned int backslashes = 0;
  for (char c : value) {
    if (c == '\\') {
      ++backslashes;
      continue;
    }
    if (c == '"') {
      quoted.append(backslashes * 2 + 1, '\\');
      quoted.push_back('"');
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, '\\');
    backslashes = 0;
    quoted.push_back(c);
  }
  quoted.append(backslashes * 2, '\\');
  quoted.push_back('"');
  return quoted;
}

bool start_helper_direct(const std::string &helper_path,
                         const std::string &args, int *pid) {
  std::string cmdline = quote_arg(helper_path) + " " + args;
  std::vector<char> mutable_cmd(cmdline.begin(), cmdline.end());
  mutable_cmd.push_back('\0');

  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {};
  BOOL created =
      CreateProcessA(helper_path.c_str(), mutable_cmd.data(), NULL, NULL, FALSE,
                     CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
  if (!created)
    return false;

  if (pid)
    *pid = static_cast<int>(pi.dwProcessId);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return true;
}

struct ElevatedLaunchState {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  bool ok = false;
  DWORD error = ERROR_SUCCESS;
  int pid = -1;
};

void finish_elevated_launch(const std::shared_ptr<ElevatedLaunchState> &state,
                            bool ok, DWORD error, int pid) {
  {
    std::lock_guard<std::mutex> lock(state->mutex);
    state->done = true;
    state->ok = ok;
    state->error = error;
    state->pid = pid;
  }
  state->cv.notify_all();
}

bool start_helper_elevated_with_timeout(const std::string &helper_path,
                                        const std::string &args, int *pid,
                                        DWORD *error) {
  auto state = std::make_shared<ElevatedLaunchState>();
  std::thread([state, helper_path, args] {
    SHELLEXECUTEINFOA sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = helper_path.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExA(&sei)) {
      finish_elevated_launch(state, false, GetLastError(), -1);
      return;
    }

    int launched_pid = -1;
    if (sei.hProcess) {
      launched_pid = static_cast<int>(GetProcessId(sei.hProcess));
      CloseHandle(sei.hProcess);
    }
    finish_elevated_launch(state, true, ERROR_SUCCESS, launched_pid);
  }).detach();

  std::unique_lock<std::mutex> lock(state->mutex);
  if (!state->cv.wait_for(lock, std::chrono::seconds(15),
                          [&] { return state->done; })) {
    if (error)
      *error = WAIT_TIMEOUT;
    return false;
  }

  if (pid)
    *pid = state->pid;
  if (error)
    *error = state->error;
  return state->ok;
}

} // namespace

OneshotBackend start_oneshot_helper(const OneshotBootstrapRequest &request) {
  OneshotBackend backend;
  backend.transport = "named-pipe";

  if (request.helper_path.empty()) {
    backend.code = kOneshotNotSupportedCode;
    backend.message = "exv-helper.exe path is not available.";
    return backend;
  }
  if (!helper_executable_exists(request.helper_path)) {
    backend.code = kServiceStartFailedCode;
    backend.message = "exv-helper.exe was not found: " + request.helper_path;
    return backend;
  }

  // Fixed endpoint: the one-shot helper is single-instance (asserted at
  // startup), so a per-session random endpoint is unnecessary and would defeat
  // reuse/reconnect. A second instance fails the single-instance assertion and
  // exits before binding this name.
  std::string session_id = "fixed";
  backend.endpoint = "\\\\.\\pipe\\exv-oneshot";
  backend.owner = current_owner_sid();
  backend.parent_pid = static_cast<int>(GetCurrentProcessId());
  if (backend.owner.empty()) {
    backend.code = kServiceStartFailedCode;
    backend.message = "Unable to determine the current Windows owner SID.";
    return backend;
  }

  std::string args = "--oneshot --endpoint \"" + backend.endpoint +
                     "\" --owner \"" + backend.owner +
                     "\" --parent-pid " + std::to_string(backend.parent_pid);

  exv::observability::LogFacade::info("Oneshot: Generated endpoint=" + backend.endpoint + " session_id=" + session_id);
  exv::observability::LogFacade::info("Oneshot: Starting helper - is_admin=" + std::string(platform::check_root() ? "true" : "false"));

  if (platform::check_root()) {
    if (!start_helper_direct(request.helper_path, args, &backend.pid)) {
      backend.code = kServiceStartFailedCode;
      backend.message = "Failed to start elevated one-shot helper.";
      return backend;
    }
  } else {
    DWORD err = ERROR_SUCCESS;
    if (!start_helper_elevated_with_timeout(request.helper_path, args,
                                            &backend.pid, &err)) {
      if (err == WAIT_TIMEOUT) {
        backend.code = kServiceStartFailedCode;
        backend.message =
            "启动提权的一次性助手超时，请检查 UAC 提示是否被遮挡，"
            "或以管理员身份运行 start.ps1 后重试。";
        return backend;
      }
      backend.code = err == ERROR_CANCELLED ? kOneshotElevationDeniedCode
                                            : kServiceStartFailedCode;
      backend.message = err == ERROR_CANCELLED
                            ? "管理员授权已取消，请允许 UAC 提权后重试。"
                            : "启动提权的一次性助手失败，请以管理员身份运行 start.ps1 后重试。";
      return backend;
    }
  }

  DWORD wait_error = ERROR_SUCCESS;
  if (!wait_for_helper_pipe_available(backend.endpoint, &wait_error)) {
    exv::observability::LogFacade::error(
        "Oneshot: Helper pipe did not become available - endpoint=" +
        backend.endpoint + " last_error=" + std::to_string(wait_error));
    backend.code = kHelperRpcFailedCode;
    backend.message = "One-shot helper did not become ready.";
    return backend;
  }

  exv::observability::LogFacade::info("Oneshot: Helper started successfully - endpoint=" + backend.endpoint + " pid=" + std::to_string(backend.pid));
  backend.ok = true;
  return backend;
}

} // namespace platform
} // namespace exv
