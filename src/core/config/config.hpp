#pragma once

#include "generated/distribution_config.hpp"
#include "platform/common/config_defaults.hpp"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace exv {
namespace config_detail {

inline std::vector<std::string> default_distribution_routes() {
  std::vector<std::string> routes;
  routes.reserve(distribution::kDefaultRoutes.size());
  for (const auto route : distribution::kDefaultRoutes) {
    routes.emplace_back(route);
  }
  return routes;
}

inline bool is_valid_dtls_mode(const std::string &mode) {
  return mode == "auto" || mode == "enabled" || mode == "disabled";
}

inline std::string dtls_mode_from_legacy_disable(bool disable_dtls) {
  return disable_dtls ? "disabled" : "auto";
}

inline int normalize_retry_limit(int retry_limit) {
  return retry_limit < 0 ? 0 : retry_limit;
}

} // namespace config_detail

struct Config {
  std::string server = std::string(distribution::kDefaultVpnServer);
  std::string username = "";
  std::string password =
      ""; // AES-256-CBC ciphertext (base64); empty if remember_password=false
  int mtu = 1290;
  std::string useragent = platform::config_defaults().useragent;
  bool disable_dtls = platform::config_defaults().disable_dtls;
  std::string dtls_mode =
      config_detail::dtls_mode_from_legacy_disable(disable_dtls);
  bool remember_password = false; // false = prompt hidden input at connect time
  std::vector<std::string> routes = config_detail::default_distribution_routes();
  std::vector<std::string> extra_args;
  std::string log_file = platform::config_defaults().log_file;
  std::string vpn_engine = "native";
  std::string windows_tunnel_driver = "auto";
  std::string windows_tap_interface = "";
  bool auto_reconnect = true;
  int retry_limit = 0;
  bool minimal_mode = false;
  bool service_install_prompt_seen = false;
  bool minimal_install_service_before_connect = true;
  bool include_class_a_private_routes = false;
  bool include_class_b_private_routes = false;
  bool launch_at_login = false;
  bool auto_connect_on_launch = false;
  bool silent_startup = false;
  bool connection_state_notifications = false;

};

inline void normalize_native_only(Config &cfg) {
  cfg.vpn_engine = "native";
  if (!config_detail::is_valid_dtls_mode(cfg.dtls_mode)) {
    cfg.dtls_mode = config_detail::dtls_mode_from_legacy_disable(cfg.disable_dtls);
  }
  cfg.disable_dtls = cfg.dtls_mode == "disabled";
  cfg.retry_limit = config_detail::normalize_retry_limit(cfg.retry_limit);
}

inline void to_json(nlohmann::json &j, const Config &cfg) {
  Config normalized = cfg;
  normalize_native_only(normalized);
  j = nlohmann::json{
      {"server", normalized.server},
      {"username", normalized.username},
      {"password", normalized.password},
      {"mtu", normalized.mtu},
      {"useragent", normalized.useragent},
      {"disable_dtls", normalized.disable_dtls},
      {"dtls_mode", normalized.dtls_mode},
      {"remember_password", normalized.remember_password},
      {"routes", normalized.routes},
      {"extra_args", normalized.extra_args},
      {"log_file", normalized.log_file},
      {"vpn_engine", normalized.vpn_engine},
      {"windows_tunnel_driver", normalized.windows_tunnel_driver},
      {"windows_tap_interface", normalized.windows_tap_interface},
      {"auto_reconnect", normalized.auto_reconnect},
      {"retry_limit", normalized.retry_limit},
      {"minimal_mode", normalized.minimal_mode},
      {"service_install_prompt_seen", normalized.service_install_prompt_seen},
      {"minimal_install_service_before_connect",
       normalized.minimal_install_service_before_connect},
      {"include_class_a_private_routes",
       normalized.include_class_a_private_routes},
      {"include_class_b_private_routes",
       normalized.include_class_b_private_routes},
      {"launch_at_login", normalized.launch_at_login},
      {"auto_connect_on_launch", normalized.auto_connect_on_launch},
      {"silent_startup", normalized.silent_startup},
      {"connection_state_notifications",
       normalized.connection_state_notifications},
  };
}

inline void from_json(const nlohmann::json &j, Config &cfg) {
  Config defaults;
  cfg = defaults;

  cfg.server = j.value("server", cfg.server);
  cfg.username = j.value("username", cfg.username);
  cfg.password = j.value("password", cfg.password);
  cfg.mtu = j.value("mtu", cfg.mtu);
  cfg.useragent = j.value("useragent", cfg.useragent);
  cfg.disable_dtls = j.value("disable_dtls", cfg.disable_dtls);
  const bool has_dtls_mode = j.contains("dtls_mode") && j["dtls_mode"].is_string();
  cfg.dtls_mode = has_dtls_mode
                      ? j["dtls_mode"].get<std::string>()
                      : config_detail::dtls_mode_from_legacy_disable(
                            cfg.disable_dtls);
  cfg.remember_password = j.value("remember_password", cfg.remember_password);
  cfg.routes = j.value("routes", cfg.routes);
  cfg.extra_args = j.value("extra_args", cfg.extra_args);
  cfg.log_file = j.value("log_file", cfg.log_file);
  cfg.vpn_engine = j.value("vpn_engine", cfg.vpn_engine);
  cfg.windows_tunnel_driver =
      j.value("windows_tunnel_driver", cfg.windows_tunnel_driver);
  cfg.windows_tap_interface =
      j.value("windows_tap_interface", cfg.windows_tap_interface);
  cfg.auto_reconnect = j.value("auto_reconnect", cfg.auto_reconnect);
  cfg.retry_limit = config_detail::normalize_retry_limit(
      j.value("retry_limit", cfg.retry_limit));
  cfg.minimal_mode = j.value("minimal_mode", cfg.minimal_mode);
  cfg.service_install_prompt_seen =
      j.value("service_install_prompt_seen", cfg.service_install_prompt_seen);
  cfg.minimal_install_service_before_connect =
      j.value("minimal_install_service_before_connect",
              cfg.minimal_install_service_before_connect);
  cfg.include_class_a_private_routes =
      j.value("include_class_a_private_routes",
              cfg.include_class_a_private_routes);
  cfg.include_class_b_private_routes =
      j.value("include_class_b_private_routes",
              cfg.include_class_b_private_routes);
  cfg.launch_at_login = j.value("launch_at_login", cfg.launch_at_login);
  cfg.auto_connect_on_launch =
      j.value("auto_connect_on_launch", cfg.auto_connect_on_launch);
  cfg.silent_startup = j.value("silent_startup", cfg.silent_startup);
  cfg.connection_state_notifications =
      j.value("connection_state_notifications",
              cfg.connection_state_notifications);
  normalize_native_only(cfg);
}

namespace config {

// Load config (creates default + key on first run)
Config load();
bool save(const Config &cfg);

// Display config with password/key status
void show(const Config &cfg);

// Import from external JSON file (merges, re-encrypts password if present)
Config import_from(const std::string &path);

// Set a key-value. For "password", prompts hidden input and encrypts.
bool set_value(Config &cfg, const std::string &key,
               const std::string &value = "");

// Decrypt the stored password ciphertext using current key file.
// Returns "" and prints an error if key is missing/corrupt.
std::string get_plaintext_password(const Config &cfg);

// Reset config to defaults (keeps key file intact)
Config reset();

// Route management
bool add_route(Config &cfg, const std::string &route);
bool remove_route(Config &cfg, const std::string &route);
void list_routes(const Config &cfg);

// Key management subcommands
void key_show();
bool key_reset();

} // namespace config
} // namespace exv
