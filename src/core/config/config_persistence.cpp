#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_paths.hpp"
#include "core/config/config_initialization.hpp"
#include "core/config/config.hpp"
#include "core/crypto/crypto.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "cli/console.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

namespace exv {
namespace config {
namespace {

std::string config_path() {
  return platform::get_config_dir() + "/config.json";
}

} // namespace

// ── Load ─────────────────────────────────────────────────────────

Config load() {
  const auto initialized = ensure_initialized_config(platform::get_config_dir());
  Config cfg = initialized.config;
  normalize_native_only(cfg);
  if (initialized.status == ConfigInitializationStatus::Missing) {
    crypto::init_key_if_needed();
  }
  if (initialized.status == ConfigInitializationStatus::Invalid) {
    cli::print_warning(
        "config.json was invalid or incomplete; defaults were regenerated.");
  }
  return cfg;
}

// ── Save ─────────────────────────────────────────────────────────

bool save(const Config &cfg) {
  std::string path = config_path();
  try {
    nlohmann::json j = cfg;
    std::string content = j.dump(2);
    if (!platform::write_file(path, content)) {
      exv::observability::LogFacade::error("Failed to write config to: " + path);
      return false;
    }
    return true;
  } catch (const std::exception &e) {
    exv::observability::LogFacade::error("Config save error: " + std::string(e.what()));
    return false;
  }
}

// ── Import ──────────────────────────────────────────────────────

Config import_from(const std::string &path) {
  if (!platform::file_exists(path)) {
    cli::print_error("Import file not found: " + path);
    return load();
  }
  try {
    std::string content = platform::read_file(path);
    auto j = nlohmann::json::parse(content);
    Config cfg = load();

    if (j.contains("server"))
      cfg.server = j["server"].get<std::string>();
    if (j.contains("username"))
      cfg.username = j["username"].get<std::string>();
    if (j.contains("mtu"))
      cfg.mtu = j["mtu"].get<int>();
    if (j.contains("useragent"))
      cfg.useragent = j["useragent"].get<std::string>();
    if (j.contains("disable_dtls")) {
      cfg.disable_dtls = j["disable_dtls"].get<bool>();
      cfg.dtls_mode = cfg.disable_dtls ? "disabled" : "auto";
    }
    if (j.contains("dtls_mode")) {
      cfg.dtls_mode = j["dtls_mode"].get<std::string>();
      if (cfg.dtls_mode != "auto" && cfg.dtls_mode != "enabled" &&
          cfg.dtls_mode != "disabled") {
        cfg.dtls_mode = cfg.disable_dtls ? "disabled" : "auto";
      }
      cfg.disable_dtls = cfg.dtls_mode == "disabled";
    }
    if (j.contains("routes"))
      cfg.routes = j["routes"].get<std::vector<std::string>>();
    if (j.contains("extra_args"))
      cfg.extra_args = j["extra_args"].get<std::vector<std::string>>();
    if (j.contains("log_file"))
      cfg.log_file = j["log_file"].get<std::string>();
    if (j.contains("remember_password"))
      cfg.remember_password = j["remember_password"].get<bool>();
    if (j.contains("vpn_engine"))
      cfg.vpn_engine = j["vpn_engine"].get<std::string>();
    if (j.contains("windows_tunnel_driver"))
      cfg.windows_tunnel_driver =
          j["windows_tunnel_driver"].get<std::string>();
    if (j.contains("windows_tap_interface"))
      cfg.windows_tap_interface =
          j["windows_tap_interface"].get<std::string>();
    if (j.contains("auto_reconnect"))
      cfg.auto_reconnect = j["auto_reconnect"].get<bool>();
    if (j.contains("retry_limit"))
      cfg.retry_limit = config_detail::normalize_retry_limit(
          j["retry_limit"].get<int>());
    if (j.contains("minimal_mode"))
      cfg.minimal_mode = j["minimal_mode"].get<bool>();
    if (j.contains("service_install_prompt_seen"))
      cfg.service_install_prompt_seen =
          j["service_install_prompt_seen"].get<bool>();
    if (j.contains("minimal_install_service_before_connect"))
      cfg.minimal_install_service_before_connect =
          j["minimal_install_service_before_connect"].get<bool>();
    if (j.contains("include_class_a_private_routes"))
      cfg.include_class_a_private_routes =
          j["include_class_a_private_routes"].get<bool>();
    if (j.contains("include_class_b_private_routes"))
      cfg.include_class_b_private_routes =
          j["include_class_b_private_routes"].get<bool>();
    if (j.contains("launch_at_login"))
      cfg.launch_at_login = j["launch_at_login"].get<bool>();
    if (j.contains("auto_connect_on_launch"))
      cfg.auto_connect_on_launch =
          j["auto_connect_on_launch"].get<bool>();
    if (j.contains("silent_startup"))
      cfg.silent_startup = j["silent_startup"].get<bool>();
    if (j.contains("connection_state_notifications"))
      cfg.connection_state_notifications =
          j["connection_state_notifications"].get<bool>();

    if (j.contains("password")) {
      std::string pw = j["password"].get<std::string>();
      if (!pw.empty() && cfg.remember_password) {
        std::string ks = crypto::key_status();
        if (ks == "valid") {
          cfg.password = crypto::encrypt(pw, crypto::load_key());
          cli::print_info("Password from import file encrypted and stored.");
        } else {
          cli::print_warning("Key is " + ks +
                               " — password from import NOT stored.");
        }
      }
    }

    normalize_native_only(cfg);
    save(cfg);
    cli::print_success("Config imported from: " + path);
    exv::observability::LogFacade::info("Config imported from: " + path);
    return cfg;
  } catch (const std::exception &e) {
    cli::print_error("Failed to import: " + std::string(e.what()));
    exv::observability::LogFacade::error("Config import error: " + std::string(e.what()));
    return load();
  }
}

// ── Reset ───────────────────────────────────────────────────────

Config reset() {
  Config cfg;
  normalize_native_only(cfg);
  save(cfg);
  cli::print_success("Config reset to defaults. Key file preserved.");
  cli::print_info("Run 'exv config set password' to set a new password.");
  exv::observability::LogFacade::info("Config reset to defaults");
  return cfg;
}

} // namespace config
} // namespace exv
