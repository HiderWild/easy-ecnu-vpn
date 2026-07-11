#include "core/config/config_initialization.hpp"

#include "generated/distribution_config.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/file_system.hpp"
#include "platform/common/path_utils.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace exv::config {
namespace {

using json = nlohmann::json;

bool is_string_array(const json &value) {
  if (!value.is_array()) {
    return false;
  }
  for (const auto &item : value) {
    if (!item.is_string()) {
      return false;
    }
  }
  return true;
}

bool field_type_matches(std::string_view name, const json &value) {
  if (name == "dtls_mode") {
    return value.is_string() &&
           exv::config_detail::is_valid_dtls_mode(value.get<std::string>());
  }
  if (name == "server" || name == "username" || name == "password" ||
      name == "useragent" || name == "log_file" || name == "vpn_engine" ||
      name == "windows_tunnel_driver" || name == "windows_tap_interface") {
    return value.is_string();
  }
  if (name == "mtu") {
    return value.is_number_integer();
  }
  if (name == "retry_limit") {
    return value.is_number_integer() && value.get<int>() >= 0;
  }
  if (name == "disable_dtls" || name == "remember_password" ||
      name == "auto_reconnect" || name == "minimal_mode" ||
      name == "service_install_prompt_seen" ||
      name == "minimal_install_service_before_connect" ||
      name == "include_class_a_private_routes" ||
      name == "include_class_b_private_routes" ||
      name == "launch_at_login" || name == "auto_connect_on_launch" ||
      name == "silent_startup" ||
      name == "connection_state_notifications") {
    return value.is_boolean();
  }
  if (name == "routes" || name == "extra_args") {
    return is_string_array(value);
  }
  return false;
}

constexpr std::string_view kRequiredFields[] = {
    "server",
    "username",
    "password",
    "mtu",
    "useragent",
    "disable_dtls",
    "dtls_mode",
    "remember_password",
    "routes",
    "extra_args",
    "log_file",
    "vpn_engine",
    "windows_tunnel_driver",
    "windows_tap_interface",
    "auto_reconnect",
    "retry_limit",
    "minimal_mode",
    "service_install_prompt_seen",
    "minimal_install_service_before_connect",
    "include_class_a_private_routes",
    "include_class_b_private_routes",
    "launch_at_login",
    "auto_connect_on_launch",
    "silent_startup",
    "connection_state_notifications",
};

Config default_config() {
  Config cfg;
  normalize_native_only(cfg);
  return cfg;
}

bool write_config(const std::string &config_dir, const Config &cfg) {
  namespace fs = std::filesystem;
  std::error_code ec;
  fs::create_directories(fs::u8path(config_dir), ec);

  const std::string final_path = platform::config_path(config_dir);
  const std::string tmp_path = final_path + ".tmp";
  const json serialized = cfg;

  if (!platform::write_file(tmp_path, serialized.dump(4))) {
    exv::observability::LogFacade::error(
        "ensure_initialized_config: failed to write temp config: " + tmp_path);
    return false;
  }

  fs::remove(fs::u8path(final_path), ec);
  ec.clear();
  fs::rename(fs::u8path(tmp_path), fs::u8path(final_path), ec);
  if (!ec) {
    return true;
  }

  ec.clear();
  fs::copy_file(fs::u8path(tmp_path), fs::u8path(final_path),
                fs::copy_options::overwrite_existing, ec);
  fs::remove(fs::u8path(tmp_path), ec);
  if (ec) {
    exv::observability::LogFacade::error(
        "ensure_initialized_config: failed to replace config: " + ec.message());
    return false;
  }
  return true;
}

ConfigInitializationResult repaired_result(ConfigInitializationStatus status,
                                           const std::string &reason,
                                           const std::string &config_dir) {
  Config cfg = default_config();
  (void)write_config(config_dir, cfg);
  return ConfigInitializationResult{status, cfg, reason};
}

ConfigInitializationResult repaired_object_result(const json &value,
                                                  const std::string &reason,
                                                  const std::string &config_dir) {
  json repaired = value;
  const json defaults = default_config();
  const bool has_valid_dtls_mode =
      repaired.contains("dtls_mode") && repaired["dtls_mode"].is_string() &&
      exv::config_detail::is_valid_dtls_mode(
          repaired["dtls_mode"].get<std::string>());
  if (!has_valid_dtls_mode &&
      repaired.contains("disable_dtls") && repaired["disable_dtls"].is_boolean()) {
    repaired["dtls_mode"] = repaired["disable_dtls"].get<bool>() ? "disabled"
                                                                : "auto";
  }
  for (const auto field : kRequiredFields) {
    const std::string field_name(field);
    if (!repaired.contains(field_name) ||
        !field_type_matches(field, repaired.at(field_name))) {
      repaired[field_name] = defaults.at(field_name);
    }
  }

  Config cfg = repaired.get<Config>();
  normalize_native_only(cfg);
  (void)write_config(config_dir, cfg);
  return ConfigInitializationResult{ConfigInitializationStatus::Invalid, cfg,
                                    reason};
}

const char *status_reason(ConfigInitializationStatus status) {
  switch (status) {
  case ConfigInitializationStatus::Missing:
    return "missing";
  case ConfigInitializationStatus::Invalid:
    return "invalid";
  case ConfigInitializationStatus::Normal:
  default:
    return "normal";
  }
}

} // namespace

bool is_complete_initialized_config_json(const json &value,
                                         std::string *reason) {
  if (!value.is_object()) {
    if (reason) {
      *reason = "type:root";
    }
    return false;
  }

  for (const auto field : kRequiredFields) {
    const std::string field_name(field);
    if (!value.contains(field_name)) {
      if (reason) {
        *reason = "missing:" + field_name;
      }
      return false;
    }
    if (!field_type_matches(field, value.at(field_name))) {
      if (reason) {
        *reason = "type:" + field_name;
      }
      return false;
    }
  }
  if (reason) {
    *reason = "normal";
  }
  return true;
}

ConfigInitializationResult ensure_initialized_config(
    const std::string &config_dir) {
  const std::string path = platform::config_path(config_dir);
  if (!platform::file_exists(path)) {
    return repaired_result(ConfigInitializationStatus::Missing, "missing",
                           config_dir);
  }

  try {
    const auto parsed = json::parse(platform::read_file(path));
    std::string completeness_reason;
	    if (!is_complete_initialized_config_json(parsed, &completeness_reason)) {
	      exv::observability::LogFacade::warn(
	          "ensure_initialized_config: invalid config completeness: " +
	          completeness_reason);
	      if (parsed.is_object()) {
	        return repaired_object_result(parsed, completeness_reason, config_dir);
	      }
	      return repaired_result(ConfigInitializationStatus::Invalid,
	                             completeness_reason, config_dir);
	    }

    Config cfg = parsed.get<Config>();
    normalize_native_only(cfg);
    return ConfigInitializationResult{ConfigInitializationStatus::Normal, cfg,
                                      "normal"};
  } catch (const std::exception &error) {
    exv::observability::LogFacade::error(
        "ensure_initialized_config: parse error: " + std::string(error.what()));
    return repaired_result(ConfigInitializationStatus::Invalid, "parse",
                           config_dir);
  }
}

nlohmann::json quick_start_request_data(
    const ConfigInitializationResult &result) {
  return json{{"reason", status_reason(result.status)},
              {"defaults",
               json{{"server", std::string(distribution::kDefaultVpnServer)},
                    {"remember_password", false},
                    {"install_service", true}}}};
}

} // namespace exv::config
