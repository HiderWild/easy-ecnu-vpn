#pragma once
#include <string>
namespace exv::platform {

// Result of launching an elevated service-management process.
struct ElevatedServiceLaunchResult {
  bool launched = false;        // true if the elevated process was started
  std::string code;             // error code on failure (e.g. "elevation_denied")
  std::string message;          // human-readable message
};

// Launch `exv-helper.exe --install-service` (and uninstall/repair) elevated.
// subcommand ∈ {"install-service","uninstall-service","repair-service"}.
// The helper executable is resolved next to the current executable
// (get_executable_path().parent_path() / "exv-helper.exe" on Windows;
//  equivalent sibling-binary resolution on POSIX).
// Returns launched=true once the elevated process has been started
// (it runs asynchronously; the caller polls service status afterward).
ElevatedServiceLaunchResult launch_elevated_service_op(const std::string &subcommand);

// ---- Test seams (production code ignores these; tests override behavior) ----

// Signature of the underlying elevated-launch primitive. Returns true if the
// elevated process was started; on false, sets *out_error to a sentinel the
// caller maps to an error code (e.g. "ERROR_CANCELLED" -> elevation_denied).
using RunasLaunchFn = bool (*)(const std::string &file,
                               const std::string &params,
                               std::string *out_error);

// Override the runas primitive. Pass nullptr to restore the default (real
// ShellExecuteExA on Windows, POSIX stub otherwise).
void set_runas_seam_for_test(RunasLaunchFn fn);

// Override the resolved helper executable path. When non-empty, this path is
// used verbatim (and checked for existence) instead of resolving the sibling
// binary next to the current executable. Pass "" to restore the default
// resolver. Used by tests to drive the helper_not_found path.
void set_helper_path_seam_for_test(const std::string &path);

} // namespace exv::platform
