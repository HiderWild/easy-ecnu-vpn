#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace exv {
namespace platform {

struct ServiceStatusSnapshot {
  bool installed = false;
  bool running = false;
  bool available = false;
  nlohmann::json capabilities = nlohmann::json::object();
  std::string mode;
  std::string path;
  std::string endpoint;
  std::string label;
  std::string binary_path;
  std::string warning;
  std::string health;
  std::string diagnostic_code;
  std::string recommended_action;
  std::string last_start_api;
  int last_start_native_error = 0;
  std::string last_start_native_message;
  std::uint32_t process_id = 0;
  bool endpoint_reachable = false;
  int service_state = 0;
  bool has_service_state = false;
};

std::string runtime_source_from_paths(const std::string &resolved_path,
                                      const std::string &bundled_path,
                                      const std::string &system_path);

nlohmann::json service_status_to_json(const ServiceStatusSnapshot &status);

} // namespace platform
} // namespace exv
