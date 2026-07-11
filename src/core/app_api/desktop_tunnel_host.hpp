#pragma once

#include "core/tunnel_controller/tunnel_controller_fwd.hpp"

#include <memory>
#include <string>

namespace exv::helper {
class HelperClient;
class HelperConnector;
}

namespace exv {
namespace app_api {

std::string helper_binary_next_to_exv();
std::shared_ptr<exv::core::TunnelController>
ensure_tunnel_controller(const std::string &endpoint_override = "");
std::shared_ptr<exv::core::TunnelController>
get_tunnel_controller_if_exists();
std::shared_ptr<exv::helper::HelperClient>
get_current_helper_client_if_exists();
void reset_tunnel_controller();
std::string tunnel_controller_init_error();

} // namespace app_api
} // namespace exv
