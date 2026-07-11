#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "platform/common/oneshot_bootstrap.hpp"

#include "helper/common/helper_messages.hpp"
#include "platform/common/backend_resolver.hpp"
#include "observability/log_facade.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <string>
#include <unistd.h>

namespace exv {
namespace platform {
namespace {


// Wait for the one-shot helper's endpoint socket to appear on disk.
//
// We deliberately do NOT open a connection to probe readiness here. The one-shot
// helper treats each client connection as a single session: a client that
// disconnects without acquiring a core lease triggers immediate cleanup and
// daemon exit. Any connect-then-close probe (the previous implementation, which
// sent Hello over a fresh short-lived connection per retry) therefore kills the
// helper on the first close, and every subsequent retry connects to a dead
// socket. Instead we only check that the helper has bound its listening socket
// (the socket file appears once bind() succeeds, and start() proceeds to
// listen() before the daemon accepts). The caller then opens the single
// long-lived connection that will carry Hello, core-lease acquisition, and the
// privileged operation -- no intermediate close, no exit-triggering disconnect.
bool wait_for_helper_endpoint(const std::string &endpoint) {
  for (int i = 0; i < 80; ++i) {
    if (platform::file_exists(endpoint)) {
      // Give the helper a beat to finish listen() after the file appeared, so
      // the caller's connect() does not race a half-open socket.
      usleep(50000);
      return true;
    }
    usleep(100000);
  }
  exv::observability::LogFacade::warn(
      "One-shot helper endpoint never appeared: " + endpoint);
  return false;
}

std::string apple_script_string(const std::string &value) {
  std::string out = "\"";
  for (char ch : value) {
    if (ch == '\\' || ch == '"')
      out.push_back('\\');
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

} // namespace

OneshotBackend start_oneshot_helper(const OneshotBootstrapRequest &request) {
  OneshotBackend backend;
  backend.transport = "unix-socket";

  if (request.helper_path.empty()) {
    backend.code = kOneshotNotSupportedCode;
    backend.message = "exv-helper path is not available.";
    return backend;
  }

  // Fixed per-user endpoint: the one-shot helper is single-instance (asserted
  // at startup via flock), so a per-session random endpoint is unnecessary.
  std::string session_id = "fixed";
  backend.endpoint = "/tmp/exv-" + std::to_string(getuid()) + "-oneshot.sock";
  backend.owner = std::to_string(getuid());
  backend.parent_pid = static_cast<int>(getpid());

  std::string command = platform::shell_quote(request.helper_path) +
                        " --oneshot --endpoint " +
                        platform::shell_quote(backend.endpoint) +
                        " --owner " +
                        platform::shell_quote(backend.owner) +
                        " --parent-pid " +
                        std::to_string(backend.parent_pid) +
                        " >/dev/null 2>&1 &";
  std::string osascript =
      "osascript -e " +
      platform::shell_quote("do shell script " + apple_script_string(command) +
                         " with administrator privileges");

  int rc = platform::run_command(osascript);
  if (rc != 0) {
    backend.code = kOneshotElevationDeniedCode;
    backend.message = "Administrator authorization was cancelled or failed.";
    return backend;
  }

  if (!wait_for_helper_endpoint(backend.endpoint)) {
    backend.code = kHelperRpcFailedCode;
    backend.message = "One-shot helper did not become ready.";
    return backend;
  }

  backend.ok = true;
  return backend;
}

} // namespace platform
} // namespace exv
