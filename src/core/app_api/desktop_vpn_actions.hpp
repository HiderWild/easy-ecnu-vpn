#pragma once

#include <nlohmann/json.hpp>

namespace exv::core_api {
class DesktopRpcAdapter;
}

namespace exv {
namespace app_api {

void register_desktop_vpn_actions(exv::core_api::DesktopRpcAdapter &adapter);
void shutdown_desktop_vpn_runtime();
void apply_desktop_connect_job_status(
    nlohmann::json *status,
    bool preserve_controller_snapshot = false);
void apply_desktop_connect_error(nlohmann::json *status);

} // namespace app_api
} // namespace exv
