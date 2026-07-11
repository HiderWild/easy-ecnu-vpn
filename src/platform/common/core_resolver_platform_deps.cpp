#include "platform/common/core_resolver_platform_deps.hpp"

#include "cli/pipe_client.hpp"
#include "platform/common/process_utils.hpp"
#include "runtime/runtime_context.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#endif

#include <memory>

namespace exv::core::lifecycle {
namespace {

bool platform_try_connect_ipc(const std::string &ipc_path) {
#ifdef _WIN32
  return WaitNamedPipeA(ipc_path.c_str(), 50) != 0;
#else
  exv::cli::PipeClient client;
  bool ok = client.connect(ipc_path);
  if (ok) {
    client.disconnect();
  }
  return ok;
#endif
}

std::string platform_send_ipc_request(const std::string &ipc_path,
                                      const std::string &request_line) {
  exv::cli::PipeClient client;
  if (!client.connect(ipc_path)) {
    return {};
  }
  std::string response = client.send_request(request_line);
  client.disconnect();
  return response;
}

void platform_disconnect_ipc() {}

bool platform_is_pid_alive(int pid) {
  if (pid <= 0) {
    return false;
  }
#ifdef _WIN32
  HANDLE process =
      OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                   static_cast<DWORD>(pid));
  if (process == nullptr) {
    return false;
  }
  DWORD exit_code = 0;
  if (!GetExitCodeProcess(process, &exit_code)) {
    CloseHandle(process);
    return false;
  }
  CloseHandle(process);
  return exit_code == STILL_ACTIVE;
#else
  return kill(static_cast<pid_t>(pid), 0) == 0;
#endif
}

bool platform_launch_core(const std::string &core_path,
                          const std::string &state_dir,
                          const std::string &home_dir) {
  std::string args = "--mode=core --daemon";
  if (!state_dir.empty()) {
    args += " --config-dir " + exv::platform::shell_quote(state_dir);
  }
  if (!home_dir.empty()) {
    args += " --home " + exv::platform::shell_quote(home_dir);
  }
#ifdef _WIN32
  if (!exv::platform::check_root()) {
    SHELLEXECUTEINFOA sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = core_path.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExA(&sei)) {
      return false;
    }
    if (sei.hProcess) {
      CloseHandle(sei.hProcess);
    }
    return true;
  }

  std::string cmd = exv::platform::shell_quote(core_path) + " " + args;
  cmd += " 2>nul";
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {};
  char cmd_buf[4096] = {};
  std::strncpy(cmd_buf, cmd.c_str(), sizeof(cmd_buf) - 1);
  if (!CreateProcessA(nullptr, cmd_buf, nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr,
                      &si, &pi)) {
    return false;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return true;
#else
  std::string cmd = exv::platform::shell_quote(core_path) + " " + args;
  cmd += " 2>/dev/null &";
  return std::system(cmd.c_str()) == 0;
#endif
}

} // namespace

CoreResolverDeps make_platform_core_resolver_deps() {
  CoreResolverDeps deps;
  auto ipc_session = std::make_shared<exv::cli::PipeClient>();
  deps.open_ipc_session = [ipc_session](const std::string &ipc_path) {
    if (ipc_session->is_connected()) {
      return true;
    }
    return ipc_session->connect(ipc_path);
  };
  deps.send_ipc_session_request = [ipc_session](
                                      const std::string &request_line) {
    std::string response = ipc_session->send_request(request_line);
    if (response.empty()) {
      ipc_session->disconnect();
    }
    return response;
  };
  deps.close_ipc_session = [ipc_session] {
    ipc_session->disconnect();
  };
  deps.try_connect_ipc = platform_try_connect_ipc;
  deps.send_ipc_request = platform_send_ipc_request;
  deps.disconnect_ipc = platform_disconnect_ipc;
  deps.launch_core = platform_launch_core;
  deps.get_frontend_executable_path = exv::platform::get_executable_path;
  deps.run_command_output = exv::platform::run_command_output;
  deps.is_pid_alive = platform_is_pid_alive;
  deps.get_state_dir = []() { return exv::runtime::paths().state_dir; };
  deps.get_home_dir = []() { return exv::runtime::paths().home; };
  deps.get_env_var = [](const std::string &name) -> std::string {
    const char *value = std::getenv(name.c_str());
    return value ? std::string(value) : std::string();
  };
  return deps;
}

} // namespace exv::core::lifecycle
