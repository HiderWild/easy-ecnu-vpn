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
namespace {

bool contains_token(const std::string &text, const std::string &token) {
  return !token.empty() && text.find(token) != std::string::npos;
}

} // namespace

ServiceStatusSnapshot current_service_status() {
  const auto &config = helper_platform_config();
  ServiceStatusSnapshot status;
  bool plist_exists = platform::file_exists(config.service_definition_path);
  std::string plist_content =
      plist_exists ? platform::read_file(config.service_definition_path) : "";
  bool helper_binary_exists =
      platform::file_exists(config.default_service_binary_path);
  bool helper_service_declared =
      contains_token(plist_content, config.default_service_binary_path) &&
      contains_token(plist_content, "--service");

  status.installed =
      plist_exists && helper_service_declared && helper_binary_exists;
  status.available = helper::is_available();
  status.running = status.available;
  status.mode = config.service_mode;
  status.path = config.service_definition_path;
  status.endpoint = config.endpoint;
  status.label = config.service_label;
  if (helper_service_declared)
    status.binary_path = config.default_service_binary_path;

  if (plist_exists && !helper_service_declared) {
    status.warning =
        "LaunchDaemon exists, but it does not point to " +
        std::string(config.default_service_binary_path) + " --service.";
  } else if (helper_service_declared && !helper_binary_exists) {
    status.warning =
        "LaunchDaemon points to " +
        std::string(config.default_service_binary_path) +
        " --service, but the stable exv-helper binary is missing.";
  }

  status.capabilities = nlohmann::json{{"service_mode", true},
                                       {"oneshot_mode", true},
                                       {"temporary_connect", true},
                                       {"direct_fallback", false},
                                       {"helper_binary", true}};
  return status;
}

ServiceStartResult try_start_helper_service() {
  const auto &config = helper_platform_config();
  std::string label = config.service_label;
  if (label.empty()) {
    return ServiceStartResult{false, "service_label_missing",
                              "Helper service label is empty."};
  }
  std::string domain = "system";
  const auto slash = label.find('/');
  if (slash != std::string::npos) {
    domain = label.substr(0, slash);
    label = label.substr(slash + 1);
  }
  std::string cmd =
      "launchctl kickstart -k " + domain + "/" + label + " >/dev/null 2>&1";
  const int result = std::system(cmd.c_str());
  if (result == 0) {
    return ServiceStartResult{true};
  }
  ServiceStartResult out;
  out.accepted = false;
  out.code = "service_start_failed";
  out.message = "launchctl kickstart failed.";
  out.native_code = result;
  return out;
}

} // namespace platform
} // namespace exv
