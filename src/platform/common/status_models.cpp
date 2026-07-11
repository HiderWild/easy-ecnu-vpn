#include "platform/common/status_models.hpp"

namespace exv {
namespace platform {

std::string runtime_source_from_paths(const std::string &resolved_path,
                                      const std::string &bundled_path,
                                      const std::string &system_path) {
  if (resolved_path.empty())
    return "missing";
  if (!bundled_path.empty() && resolved_path == bundled_path)
    return "bundled";
  if (!system_path.empty() && resolved_path == system_path)
    return "system";
  return "custom";
}

nlohmann::json service_status_to_json(const ServiceStatusSnapshot &status) {
  nlohmann::json json{{"installed", status.installed},
                      {"running", status.running},
                      {"available", status.available},
                      {"endpoint_reachable", status.endpoint_reachable},
                      {"capabilities", status.capabilities},
                      {"mode", status.mode},
                      {"path", status.path}};

  if (!status.endpoint.empty())
    json["endpoint"] = status.endpoint;
  if (!status.label.empty())
    json["label"] = status.label;
  if (!status.binary_path.empty())
    json["binary_path"] = status.binary_path;
  if (!status.warning.empty())
    json["warning"] = status.warning;
  if (!status.health.empty())
    json["health"] = status.health;
  if (!status.diagnostic_code.empty())
    json["diagnostic_code"] = status.diagnostic_code;
  if (!status.recommended_action.empty())
    json["recommended_action"] = status.recommended_action;
  if (!status.last_start_api.empty())
    json["last_start_api"] = status.last_start_api;
  if (status.last_start_native_error != 0)
    json["last_start_native_error"] = status.last_start_native_error;
  if (!status.last_start_native_message.empty())
    json["last_start_native_message"] = status.last_start_native_message;
  if (status.process_id != 0)
    json["process_id"] = status.process_id;
  if (status.has_service_state)
    json["service_state"] = status.service_state;

  return json;
}

} // namespace platform
} // namespace exv
