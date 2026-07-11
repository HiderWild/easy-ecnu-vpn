#include "core/app_api/desktop_tunnel_host.hpp"

#include "core/use_cases/tunnel_use_cases.hpp"
#include "helper/common/helper_connector.hpp"

#include <utility>

namespace exv {
namespace app_api {

// These free functions are thin adapters that delegate to the shared
// exv::core::TunnelUseCases instance, which now owns the tunnel runtime
// (HelperConnector + HelperClient + network ops + TunnelController).  Keeping
// the adapters preserves every existing app_api caller while ensuring there is
// exactly one TunnelController shared with the native (core/rpc) entrypoint.

std::string helper_binary_next_to_exv() {
  return exv::core::TunnelUseCases::helper_binary_next_to_exv();
}

std::shared_ptr<exv::core::TunnelController>
ensure_tunnel_controller(const std::string &endpoint_override) {
  return exv::core::tunnel_use_cases().ensure_controller(endpoint_override);
}

std::shared_ptr<exv::core::TunnelController>
get_tunnel_controller_if_exists() {
  return exv::core::tunnel_use_cases().controller_if_exists();
}

std::shared_ptr<exv::helper::HelperClient>
get_current_helper_client_if_exists() {
  return exv::core::tunnel_use_cases().current_helper_client();
}

void reset_tunnel_controller() {
  exv::core::tunnel_use_cases().reset_controller();
}

std::string tunnel_controller_init_error() {
  return exv::core::tunnel_use_cases().controller_init_error();
}

} // namespace app_api
} // namespace exv
