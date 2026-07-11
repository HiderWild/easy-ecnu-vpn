#include "platform/common/oneshot_bootstrap.hpp"

#include "helper/common/helper_messages.hpp"
#include "platform/common/helper_client.hpp"
#include "platform/common/backend_resolver.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>

namespace exv {
namespace platform {
namespace {


bool wait_for_helper_hello(const HelperEndpoint &endpoint) {
  for (int i = 0; i < 40; ++i) {
    exv::helper::HelperRequest request;
    request.op = exv::helper::HelperOp::Hello;
    request.payload_json = nlohmann::json(exv::helper::HelloRequest{}).dump();
    nlohmann::json hello = send_helper_request(endpoint, nlohmann::json(request));
    if (hello.value("success", false))
      return true;
    usleep(100000);
  }
  return false;
}

pid_t spawn_helper(const std::string &helper_path, const std::string &endpoint,
                   const std::string &owner, int parent_pid) {
  const std::string parent = std::to_string(parent_pid);
  pid_t pid = fork();
  if (pid != 0)
    return pid;

  if (geteuid() == 0) {
    execl(helper_path.c_str(), helper_path.c_str(), "--oneshot", "--endpoint",
          endpoint.c_str(), "--owner", owner.c_str(), "--parent-pid",
          parent.c_str(), static_cast<char *>(nullptr));
  } else {
    execlp("pkexec", "pkexec", helper_path.c_str(), "--oneshot", "--endpoint",
           endpoint.c_str(), "--owner", owner.c_str(), "--parent-pid",
           parent.c_str(), static_cast<char *>(nullptr));
  }
  _exit(127);
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
  const std::string session_id = "fixed";
  backend.endpoint = "/tmp/exv-" + std::to_string(getuid()) + "-oneshot.sock";
  backend.owner = std::to_string(getuid());
  backend.parent_pid = static_cast<int>(getpid());

  pid_t pid = spawn_helper(request.helper_path, backend.endpoint, backend.owner,
                           backend.parent_pid);
  if (pid <= 0) {
    backend.code = kServiceStartFailedCode;
    backend.message = "Failed to start elevated one-shot helper.";
    return backend;
  }
  backend.pid = static_cast<int>(pid);

  if (!wait_for_helper_hello(HelperEndpoint{backend.endpoint})) {
    backend.code = kHelperRpcFailedCode;
    backend.message = "One-shot helper did not become ready.";
    return backend;
  }

  backend.ok = true;
  return backend;
}

} // namespace platform
} // namespace exv
