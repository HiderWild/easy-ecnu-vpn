#include "platform/common/elevated_service_launcher.hpp"

#include "platform/common/process_utils.hpp"

#include <cstring>
#include <filesystem>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#endif

namespace exv::platform {
namespace {

// Platform helper binary name resolved next to the current executable.
#ifdef _WIN32
constexpr const char *kHelperBinaryName = "exv-helper.exe";
#else
constexpr const char *kHelperBinaryName = "exv-helper";
#endif

// Resolve the helper executable next to the current executable, mirroring
// helper_service_manager.cpp's `get_executable_path().parent_path() /
// "exv-helper.exe"`.
std::string resolve_helper_path() {
  std::string exe_path = get_executable_path();
  if (exe_path.empty()) {
    return {};
  }
  std::error_code ec;
  std::filesystem::path helper =
      std::filesystem::path(exe_path).parent_path() / kHelperBinaryName;
  return helper.string();
}

#ifdef _WIN32
// Real Win32 runas primitive matching core_resolver_platform_deps.cpp's
// platform_launch_core pattern: SHELLEXECUTEINFOA, lpVerb="runas",
// SEE_MASK_NOCLOSEPROCESS, nShow=SW_HIDE. Does NOT wait for the elevated
// process (callers poll service status). Returns true once started; on false
// sets *out_error to an "ERROR_<code>" sentinel the caller maps to a code.
bool default_runas(const std::string &file, const std::string &params,
                   std::string *out_error) {
  SHELLEXECUTEINFOA sei = {};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS;
  sei.lpVerb = "runas";
  sei.lpFile = file.c_str();
  sei.lpParameters = params.c_str();
  sei.nShow = SW_HIDE;
  if (!ShellExecuteExA(&sei)) {
    DWORD err = GetLastError();
    if (out_error) {
      *out_error = "ERROR_" + std::to_string(err);
    }
    return false;
  }
  if (sei.hProcess) {
    CloseHandle(sei.hProcess);
  }
  return true;
}

// Direct (non-elevated) launch used when the caller is already elevated, so a
// redundant UAC prompt is avoided. Mirrors the CreateProcessA branch of
// platform_launch_core. Returns true once started; on false sets *out_error.
bool default_direct_launch(const std::string &file, const std::string &params,
                           std::string *out_error) {
  std::string cmd = shell_quote(file) + " " + params;
  cmd += " 2>nul";
  STARTUPINFOA si = {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {};
  char cmd_buf[4096] = {};
  std::strncpy(cmd_buf, cmd.c_str(), sizeof(cmd_buf) - 1);
  if (!CreateProcessA(nullptr, cmd_buf, nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr,
                      &si, &pi)) {
    DWORD err = GetLastError();
    if (out_error) {
      *out_error = "ERROR_" + std::to_string(err);
    }
    return false;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return true;
}
#else
// POSIX: elevated launch is Windows-only in this phase. POSIX install is
// handled separately later; do not implement here.
bool default_runas(const std::string &, const std::string &,
                   std::string *out_error) {
  if (out_error)
    *out_error = "not_implemented";
  return false;
}
#endif

// Active runas primitive. Defaults to the real implementation; tests swap it
// via set_runas_seam_for_test.
RunasLaunchFn g_runas = &default_runas;

// Test override for the resolved helper path; empty = use the real resolver.
std::string g_helper_path_override;

RunasLaunchFn effective_runas() {
  return g_runas ? g_runas : &default_runas;
}

} // namespace

void set_runas_seam_for_test(RunasLaunchFn fn) { g_runas = fn; }

void set_helper_path_seam_for_test(const std::string &path) {
  g_helper_path_override = path;
}

ElevatedServiceLaunchResult
launch_elevated_service_op(const std::string &subcommand) {
  ElevatedServiceLaunchResult result;

#ifndef _WIN32
  // POSIX stub: elevated launch is Windows-only in this phase.
  (void)subcommand;
  result.launched = false;
  result.code = "not_implemented";
  result.message = "Elevated launch is Windows-only in this phase";
  return result;
#else
  // Resolve the helper executable path (test override or sibling binary).
  std::string helper_path =
      g_helper_path_override.empty() ? resolve_helper_path()
                                     : g_helper_path_override;

  std::error_code ec;
  if (helper_path.empty() ||
      !std::filesystem::is_regular_file(helper_path, ec)) {
    result.launched = false;
    result.code = "helper_not_found";
    result.message = "exv-helper.exe was not found next to exv.exe";
    return result;
  }

  std::string params = "--" + subcommand;

  // Map a failed launch (runas or direct) to an error code. ERROR_CANCELLED
  // (1223) = user declined the UAC prompt.
  auto map_failure = [&result](const std::string &error) {
    if (error == "ERROR_CANCELLED" || error == "ERROR_1223") {
      result.launched = false;
      result.code = "elevation_denied";
      result.message = "管理员授权已取消。";
    } else {
      result.launched = false;
      result.code = "launch_failed";
      result.message = "启动提权进程失败: " + error;
    }
  };

  // Mirror platform_launch_core: when not already elevated, run the helper
  // elevated via ShellExecuteEx(runas); when already elevated, launch it
  // directly (no redundant UAC). The runas path is the seam-tested primary
  // path; the direct path reuses the proven CreateProcessA idiom.
  if (!check_root()) {
    std::string error;
    if (!effective_runas()(helper_path, params, &error)) {
      map_failure(error);
      return result;
    }
  } else {
    std::string error;
    if (!default_direct_launch(helper_path, params, &error)) {
      map_failure(error);
      return result;
    }
  }

  result.launched = true;
  result.code.clear();
  result.message.clear();
  return result;
#endif
}

} // namespace exv::platform
