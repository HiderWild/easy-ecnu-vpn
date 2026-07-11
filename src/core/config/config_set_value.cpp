#include "utils/strings.hpp"
#include "core/config/config.hpp"
#include "core/crypto/crypto.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "cli/console.hpp"

#include <iostream>
#include <string>

namespace exv {
namespace config {
namespace {

// Strip surrounding quotes that Windows CMD/PowerShell may add.
static std::string strip_quotes(const std::string &s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"')
    return s.substr(1, s.size() - 2);
  return s;
}

} // namespace

// ── set_value ────────────────────────────────────────────────────

bool set_value(Config &cfg, const std::string &key, const std::string &inline_value) {
  std::string value = strip_quotes(inline_value);

  // Helper: use inline value if provided, otherwise prompt from stdin.
  auto read_value = [&](const std::string &prompt) -> std::string {
    if (!value.empty())
      return value;
    std::cout << prompt;
    std::string val;
    std::getline(std::cin, val);
    return strip_quotes(exv::utils::trim(val));
  };

  if (key == "password") {
    if (!cfg.remember_password) {
      cli::print_warning("remember_password is currently disabled.");
      cli::print_info(
          "To store an encrypted password, it must be enabled first.");
      std::cout << std::endl;
      std::cout << "  Enable remember_password and set a password now? [Y/n]: ";
      std::string ans;
      std::getline(std::cin, ans);
      ans = exv::utils::trim(ans);
      if (!ans.empty() && ans[0] != 'y' && ans[0] != 'Y') {
        cli::print_info(
            "Aborted. Password will continue to be prompted at connect time.");
        return false;
      }
      cfg.remember_password = true;
      cli::print_success("remember_password enabled.");
    }
    std::string ks = crypto::key_status();
    if (ks != "valid") {
      cli::print_error("Encryption key is " + ks + "!");
      cli::print_info("Run 'exv config key reset' to fix this.");
      return false;
    }
    cli::print_info("Password input is hidden and will not be displayed.");
    std::string pw = crypto::read_password_hidden("  New password: ");
    if (pw.empty()) {
      cli::print_error("Password cannot be empty.");
      return false;
    }
    cfg.password = crypto::encrypt(pw, crypto::load_key());
    if (cfg.password.empty()) {
      cli::print_error("Encryption failed.");
      return false;
    }
    if (save(cfg)) {
      cli::print_success("Password set and encrypted.");
      exv::observability::LogFacade::info("Password updated (encrypted)");
      return true;
    }
    return false;
  }

  if (key == "remember_password") {
    std::string input = read_value("  Remember password? [Y/n]: ");
    if (input.empty())
      input = "y";
    cfg.remember_password = (input[0] == 'y' || input[0] == 'Y');
    if (!cfg.remember_password) {
      cfg.password = "";
      cfg.auto_connect_on_launch = false;
      crypto::delete_key_file();
    }
    if (save(cfg)) {
      cli::print_success(std::string("remember_password = ") +
                           (cfg.remember_password ? "true" : "false"));
      return true;
    }
    return false;
  }

  if (key == "disable_dtls") {
    std::string input = read_value("  Disable DTLS? [y/N]: ");
    cfg.disable_dtls = (!input.empty() && (input[0] == 'y' || input[0] == 'Y'));
    cfg.dtls_mode = cfg.disable_dtls ? "disabled" : "auto";
    if (save(cfg)) {
      cli::print_success(std::string("disable_dtls = ") +
                           (cfg.disable_dtls ? "true" : "false"));
      return true;
    }
    return false;
  }

  auto handle_bool = [&](const std::string &k, bool &field,
                         const std::string &prompt,
                         bool default_yes) -> bool {
    if (key != k)
      return false;
    std::string input = read_value(prompt);
    if (input.empty())
      input = default_yes ? "y" : "n";
    if (input == "true" || input == "1") {
      field = true;
    } else if (input == "false" || input == "0") {
      field = false;
    } else {
      field = (input[0] == 'y' || input[0] == 'Y');
    }
    if (save(cfg)) {
      cli::print_success(k + " = " + (field ? "true" : "false"));
      return true;
    }
    return false;
  };

  if (handle_bool("auto_reconnect", cfg.auto_reconnect,
                  "  Enable auto reconnect? [Y/n]: ", true))
    return true;
  if (handle_bool("minimal_mode", cfg.minimal_mode,
                  "  Enable minimal desktop mode? [Y/n]: ", true))
    return true;
  if (handle_bool("service_install_prompt_seen",
                  cfg.service_install_prompt_seen,
                  "  Mark service install prompt as seen? [y/N]: ", false))
    return true;
  if (handle_bool("minimal_install_service_before_connect",
                  cfg.minimal_install_service_before_connect,
                  "  Install service before minimal-mode connect? [Y/n]: ",
                  true))
    return true;
  if (handle_bool("include_class_a_private_routes",
                  cfg.include_class_a_private_routes,
                  "  Route all 10.0.0.0/8 private addresses through EXV? [y/N]: ",
                  false))
    return true;
  if (handle_bool("include_class_b_private_routes",
                  cfg.include_class_b_private_routes,
                  "  Route all 172.16.0.0/12 private addresses through EXV? [y/N]: ",
                  false))
    return true;
  if (handle_bool("launch_at_login", cfg.launch_at_login,
                  "  Launch EXV at login? [y/N]: ", false))
    return true;
  if (handle_bool("auto_connect_on_launch", cfg.auto_connect_on_launch,
                  "  Connect automatically when EXV starts? [y/N]: ",
                  false))
    return true;
  if (handle_bool("silent_startup", cfg.silent_startup,
                  "  Start EXV hidden on first launch? [y/N]: ", false))
    return true;
  if (handle_bool("connection_state_notifications",
                  cfg.connection_state_notifications,
                  "  Show system notifications on connect/disconnect? [y/N]: ",
                  false))
    return true;

  if (key == "vpn_engine") {
    std::string input = read_value("  VPN engine [native]: ");
    if (input != "native") {
      cli::print_error("VPN engine is native-only.");
      return false;
    }
    cfg.vpn_engine = "native";
    if (save(cfg)) {
      cli::print_success("Set vpn_engine = native");
      return true;
    }
    return false;
  }

  if (key == "windows_tunnel_driver") {
    std::string input = read_value("  Tunnel driver [auto/wintun/tap]: ");
    if (input != "auto" && input != "wintun" && input != "tap") {
      cli::print_error("Invalid tunnel driver.");
      return false;
    }
    cfg.windows_tunnel_driver = input;
    if (save(cfg)) {
      cli::print_success("Set windows_tunnel_driver = " + input);
      return true;
    }
    return false;
  }

  auto handle_str = [&](const std::string &k, std::string &field) -> bool {
    if (key != k)
      return false;
    std::string val = read_value("  Enter value for " + k + ": ");
    if (val.empty()) {
      cli::print_error("Value cannot be empty.");
      return false;
    }
    field = val;
    if (save(cfg)) {
      cli::print_success("Set " + k + " = " + val);
      return true;
    }
    return false;
  };

  if (handle_str("server", cfg.server))
    return true;
  if (handle_str("username", cfg.username))
    return true;
  if (handle_str("useragent", cfg.useragent))
    return true;
  if (handle_str("log_file", cfg.log_file))
    return true;
  if (handle_str("windows_tap_interface", cfg.windows_tap_interface))
    return true;

  if (key == "mtu") {
    std::string val = read_value("  Enter value for mtu: ");
    try {
      cfg.mtu = std::stoi(val);
    } catch (...) {
      cli::print_error("Invalid MTU.");
      return false;
    }
    if (save(cfg)) {
      cli::print_success("Set mtu = " + val);
      return true;
    }
    return false;
  }

  if (key == "retry_limit") {
    std::string val = read_value("  Enter value for retry_limit (0 = unlimited): ");
    int retry_limit = 0;
    try {
      retry_limit = std::stoi(val);
    } catch (...) {
      cli::print_error("Invalid retry_limit.");
      return false;
    }
    if (retry_limit < 0) {
      cli::print_error("retry_limit must be 0 or a positive integer.");
      return false;
    }
    cfg.retry_limit = retry_limit;
    if (save(cfg)) {
      cli::print_success("Set retry_limit = " + val);
      return true;
    }
    return false;
  }

  cli::print_error("Unknown config key: " + key);
  cli::print_info("Valid keys: server, username, password, mtu, useragent, "
                    "retry_limit, log_file, remember_password, disable_dtls, "
                    "auto_reconnect, minimal_mode, "
                    "service_install_prompt_seen, "
                    "minimal_install_service_before_connect, "
                    "include_class_a_private_routes, "
                    "include_class_b_private_routes, "
                    "launch_at_login, auto_connect_on_launch, "
                    "silent_startup, connection_state_notifications, "
                    "vpn_engine, "
                    "windows_tunnel_driver, windows_tap_interface");
  return false;
}

} // namespace config
} // namespace exv
