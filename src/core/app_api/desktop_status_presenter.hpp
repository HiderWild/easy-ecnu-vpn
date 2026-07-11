#pragma once

#include "core/config/config.hpp"
#include "core/tunnel_controller/tunnel_state.hpp"

#include <nlohmann/json.hpp>

namespace exv {
namespace app_api {

nlohmann::json frontend_status_from_helper(const nlohmann::json &helper_resp,
                                           const Config &cfg);
nlohmann::json disconnected_status(const Config &cfg);
nlohmann::json frontend_status_from_snapshot_json(const nlohmann::json &snapshot,
                                                  const Config &cfg);
nlohmann::json auth_config(const Config &cfg);
nlohmann::json settings_config(const Config &cfg);
nlohmann::json routes_json(const Config &cfg);
nlohmann::json key_status_json();
nlohmann::json service_status_json();
nlohmann::json runtime_status_json(const Config &cfg);
nlohmann::json frontend_status_from_controller_snapshot(
    const exv::core::TunnelStatusSnapshot &snap, const Config &cfg);
nlohmann::json helper_current_instance_from_controller_snapshot(
    const exv::core::TunnelStatusSnapshot &snap);
nlohmann::json driver_status_json(const Config &cfg);
nlohmann::json install_driver(const Config &cfg, const nlohmann::json &payload);
nlohmann::json drain_virtual_network_status_events();
void reset_virtual_network_probe_state_for_testing();
void expire_virtual_network_probe_cache_for_testing();

} // namespace app_api
} // namespace exv
