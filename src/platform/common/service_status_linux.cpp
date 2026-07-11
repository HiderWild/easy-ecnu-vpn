#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "platform/common/service_status.hpp"

#include "helper/helper.hpp"
#include "platform/common/helper_platform.hpp"

#include <cstdlib>
#include <string>

namespace exv {
namespace platform {

ServiceStatusSnapshot current_service_status() {
  const auto &config = helper_platform_config();
  ServiceStatusSnapshot status;
  status.installed = platform::file_exists(config.service_definition_path);
  status.available = helper::is_available();
  status.running = status.available;
  status.mode = config.service_mode;
  status.path = config.default_service_binary_path;
  status.endpoint = config.endpoint;
  status.label = config.service_label;
  status.capabilities = nlohmann::json{{"service_mode", true},
                                       {"oneshot_mode", false},
                                       {"temporary_connect", false},
                                       {"direct_fallback", false},
                                       {"helper_binary", true}};
  return status;
}

ServiceStartResult try_start_helper_service() {
  const auto &config = helper_platform_config();
  std::string unit = config.service_label;
  if (unit.empty()) {
    return ServiceStartResult{false, "service_label_missing",
                              "Helper service label is empty."};
  }
  std::string cmd = "systemctl start " + unit + " >/dev/null 2>&1";
  const int result = std::system(cmd.c_str());
  if (result == 0) {
    return ServiceStartResult{true};
  }
  ServiceStartResult out;
  out.accepted = false;
  out.code = "service_start_failed";
  out.message = "systemctl start failed.";
  out.native_code = result;
  return out;
}

} // namespace platform
} // namespace exv
