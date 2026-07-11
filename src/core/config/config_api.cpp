#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_paths.hpp"
#include "core/config/config_api.hpp"
#include "core/crypto/crypto.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace exv {
namespace config_api {

// ── CIDR validation (mirrors config.cpp) ──────────────────────────

static bool is_valid_cidr(const std::string& s) {
    if (s.empty()) return false;
    if (s.back() == '.' || s.back() == '/') return false;

    std::string ip_part = s;
    std::string::size_type slash = s.find('/');
    if (slash != std::string::npos) {
        std::string pstr = s.substr(slash + 1);
        if (pstr.empty()) return false;
        int prefix;
        try {
            prefix = std::stoi(pstr);
        } catch (...) {
            return false;
        }
        if (prefix < 0 || prefix > 32) return false;
        if (pstr.size() > 1 && pstr[0] == '0') return false;
        ip_part = s.substr(0, slash);
    }

    int octets = 0;
    std::istringstream iss(ip_part);
    std::string octet;
    while (std::getline(iss, octet, '.')) {
        if (octet.empty()) return false;
        for (char c : octet) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        int v;
        try {
            v = std::stoi(octet);
        } catch (...) {
            return false;
        }
        if (v < 0 || v > 255) return false;
        ++octets;
    }
    return octets == 4;
}

// ── Config field setters ──────────────────────────────────────────

std::string config_set(config::ConfigManager& mgr, const std::string& key,
                       const std::string& value) {
    Config cfg = mgr.load();

    if (key == "server") {
        cfg.server = value;
    } else if (key == "username") {
        cfg.username = value;
    } else if (key == "useragent") {
        cfg.useragent = value;
    } else if (key == "log_file") {
        cfg.log_file = value;
    } else if (key == "mtu") {
        int mtu;
        try {
            mtu = std::stoi(value);
        } catch (...) {
            return "Invalid MTU value";
        }
        if (mtu < 576 || mtu > 1500) return "MTU must be between 576 and 1500";
        cfg.mtu = mtu;
    } else if (key == "retry_limit") {
        int retry_limit;
        try {
            retry_limit = std::stoi(value);
        } catch (...) {
            return "Invalid integer value for retry_limit";
        }
        if (retry_limit < 0) {
            return "retry_limit must be 0 or a positive integer";
        }
        cfg.retry_limit = retry_limit;
    } else if (key == "remember_password") {
        if (value == "true" || value == "1") {
            cfg.remember_password = true;
        } else if (value == "false" || value == "0") {
            cfg.remember_password = false;
            cfg.password = "";
            cfg.auto_connect_on_launch = false;
            crypto::delete_key_file();
        } else {
            return "Invalid boolean value for remember_password";
        }
    } else if (key == "disable_dtls") {
        if (value == "true" || value == "1") {
            cfg.disable_dtls = true;
            cfg.dtls_mode = "disabled";
        } else if (value == "false" || value == "0") {
            cfg.disable_dtls = false;
            cfg.dtls_mode = "auto";
        } else {
            return "Invalid boolean value for disable_dtls";
        }
    } else if (key == "dtls_mode") {
        if (value == "auto" || value == "enabled" || value == "disabled") {
            cfg.dtls_mode = value;
            cfg.disable_dtls = value == "disabled";
        } else {
            return "dtls_mode must be auto, enabled, or disabled";
        }
    } else if (key == "auto_reconnect") {
        if (value == "true" || value == "1") {
            cfg.auto_reconnect = true;
        } else if (value == "false" || value == "0") {
            cfg.auto_reconnect = false;
        } else {
            return "Invalid boolean value for auto_reconnect";
        }
    } else if (key == "minimal_mode") {
        if (value == "true" || value == "1") {
            cfg.minimal_mode = true;
        } else if (value == "false" || value == "0") {
            cfg.minimal_mode = false;
        } else {
            return "Invalid boolean value for minimal_mode";
        }
    } else if (key == "service_install_prompt_seen") {
        if (value == "true" || value == "1") {
            cfg.service_install_prompt_seen = true;
        } else if (value == "false" || value == "0") {
            cfg.service_install_prompt_seen = false;
        } else {
            return "Invalid boolean value for service_install_prompt_seen";
        }
    } else if (key == "minimal_install_service_before_connect") {
        if (value == "true" || value == "1") {
            cfg.minimal_install_service_before_connect = true;
        } else if (value == "false" || value == "0") {
            cfg.minimal_install_service_before_connect = false;
        } else {
            return "Invalid boolean value for minimal_install_service_before_connect";
        }
    } else if (key == "include_class_a_private_routes") {
        if (value == "true" || value == "1") {
            cfg.include_class_a_private_routes = true;
        } else if (value == "false" || value == "0") {
            cfg.include_class_a_private_routes = false;
        } else {
            return "Invalid boolean value for include_class_a_private_routes";
        }
    } else if (key == "include_class_b_private_routes") {
        if (value == "true" || value == "1") {
            cfg.include_class_b_private_routes = true;
        } else if (value == "false" || value == "0") {
            cfg.include_class_b_private_routes = false;
        } else {
            return "Invalid boolean value for include_class_b_private_routes";
        }
    } else if (key == "launch_at_login") {
        if (value == "true" || value == "1") {
            cfg.launch_at_login = true;
        } else if (value == "false" || value == "0") {
            cfg.launch_at_login = false;
        } else {
            return "Invalid boolean value for launch_at_login";
        }
    } else if (key == "auto_connect_on_launch") {
        if (value == "true" || value == "1") {
            cfg.auto_connect_on_launch = true;
        } else if (value == "false" || value == "0") {
            cfg.auto_connect_on_launch = false;
        } else {
            return "Invalid boolean value for auto_connect_on_launch";
        }
    } else if (key == "silent_startup") {
        if (value == "true" || value == "1") {
            cfg.silent_startup = true;
        } else if (value == "false" || value == "0") {
            cfg.silent_startup = false;
        } else {
            return "Invalid boolean value for silent_startup";
        }
    } else if (key == "connection_state_notifications") {
        if (value == "true" || value == "1") {
            cfg.connection_state_notifications = true;
        } else if (value == "false" || value == "0") {
            cfg.connection_state_notifications = false;
        } else {
            return "Invalid boolean value for connection_state_notifications";
        }
    } else if (key == "vpn_engine") {
        if (value != "native") {
            return "vpn_engine is native-only; legacy engine has been removed";
        }
        cfg.vpn_engine = "native";
    } else if (key == "windows_tunnel_driver") {
        if (value == "auto" || value == "wintun" || value == "tap") {
            cfg.windows_tunnel_driver = value;
        } else {
            return "windows_tunnel_driver must be auto, wintun, or tap";
        }
    } else if (key == "windows_tap_interface") {
        cfg.windows_tap_interface = value;
    } else {
        return "Unknown config key: " + key;
    }

    normalize_native_only(cfg);
    if (!mgr.save(cfg)) {
        return "Failed to write config file. Check disk permissions for " +
               platform::get_config_path();
    }
    exv::observability::LogFacade::info("Config key set via config_api: " + key);
    return "";
}

std::string config_clear_password_and_key(config::ConfigManager& mgr) {
    Config cfg = mgr.load();
    cfg.remember_password = false;
    cfg.password.clear();
    cfg.auto_connect_on_launch = false;
    normalize_native_only(cfg);
    if (!mgr.save(cfg)) {
        return "Failed to write config file. Check disk permissions for " +
               platform::get_config_path();
    }
    if (!crypto::delete_key_file()) {
        return "Failed to delete encryption key file: " + crypto::key_path();
    }
    exv::observability::LogFacade::info("Stored password and encryption key cleared via config_api");
    return "";
}

std::string config_set_password(config::ConfigManager& mgr,
                                const std::string& plaintext) {
    if (plaintext.empty()) {
        return "Password cannot be empty";
    }

    Config cfg = mgr.load();

    if (!cfg.remember_password) {
        cfg.remember_password = true;
    }

    // Make sure the encryption key is available before validating. The
    // desktop entrypoint already calls init_key_if_needed() but the CLI
    // can still hit this path on a clean install.
    crypto::init_key_if_needed();

    std::string ks = crypto::key_status();
    if (ks != "valid") {
        return "Encryption key is " + ks + ". Reset key first.";
    }

    std::string key = crypto::load_key();
    std::string encrypted = crypto::encrypt(plaintext, key);
    if (encrypted.empty()) {
        return "Encryption failed";
    }

    cfg.password = encrypted;
    normalize_native_only(cfg);
    if (!mgr.save(cfg)) {
        return "Failed to write config file. Check disk permissions for " +
               platform::get_config_path();
    }
    exv::observability::LogFacade::info("Password updated via config_api (encrypted)");
    return "";
}

void config_reset(config::ConfigManager& mgr) {
    Config cfg;
    normalize_native_only(cfg);
    mgr.save(cfg);
    exv::observability::LogFacade::info("Config reset to defaults via config_api");
}

// ── Config import ─────────────────────────────────────────────────

std::string config_import(config::ConfigManager& mgr, const std::string& json_str) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(json_str);
    } catch (const std::exception& e) {
        std::ostringstream ss;
        ss << "Invalid JSON: " << e.what();
        return ss.str();
    }

    Config cfg = mgr.load();

    try {
        if (j.contains("server")) cfg.server = j["server"].get<std::string>();
        if (j.contains("username")) cfg.username = j["username"].get<std::string>();
        if (j.contains("mtu")) cfg.mtu = j["mtu"].get<int>();
        if (j.contains("useragent")) cfg.useragent = j["useragent"].get<std::string>();
        if (j.contains("disable_dtls")) {
            cfg.disable_dtls = j["disable_dtls"].get<bool>();
            cfg.dtls_mode = cfg.disable_dtls ? "disabled" : "auto";
        }
        if (j.contains("dtls_mode")) {
            cfg.dtls_mode = j["dtls_mode"].get<std::string>();
            if (cfg.dtls_mode != "auto" && cfg.dtls_mode != "enabled" &&
                cfg.dtls_mode != "disabled") {
                return "dtls_mode must be auto, enabled, or disabled";
            }
            cfg.disable_dtls = cfg.dtls_mode == "disabled";
        }
        if (j.contains("routes")) cfg.routes = j["routes"].get<std::vector<std::string>>();
        if (j.contains("extra_args")) cfg.extra_args = j["extra_args"].get<std::vector<std::string>>();
        if (j.contains("log_file")) cfg.log_file = j["log_file"].get<std::string>();
        bool clear_stored_password = false;
        if (j.contains("remember_password")) {
            cfg.remember_password = j["remember_password"].get<bool>();
            if (!cfg.remember_password) {
                clear_stored_password = true;
            }
        }
        if (j.contains("vpn_engine")) cfg.vpn_engine = j["vpn_engine"].get<std::string>();
        if (j.contains("windows_tunnel_driver")) cfg.windows_tunnel_driver = j["windows_tunnel_driver"].get<std::string>();
        if (j.contains("windows_tap_interface")) cfg.windows_tap_interface = j["windows_tap_interface"].get<std::string>();
        if (j.contains("auto_reconnect")) cfg.auto_reconnect = j["auto_reconnect"].get<bool>();
        if (j.contains("retry_limit")) {
            const int retry_limit = j["retry_limit"].get<int>();
            if (retry_limit < 0) {
                return "retry_limit must be 0 or a positive integer";
            }
            cfg.retry_limit = retry_limit;
        }
        if (j.contains("minimal_mode")) cfg.minimal_mode = j["minimal_mode"].get<bool>();
        if (j.contains("service_install_prompt_seen")) cfg.service_install_prompt_seen = j["service_install_prompt_seen"].get<bool>();
        if (j.contains("minimal_install_service_before_connect")) cfg.minimal_install_service_before_connect = j["minimal_install_service_before_connect"].get<bool>();
        if (j.contains("include_class_a_private_routes")) cfg.include_class_a_private_routes = j["include_class_a_private_routes"].get<bool>();
        if (j.contains("include_class_b_private_routes")) cfg.include_class_b_private_routes = j["include_class_b_private_routes"].get<bool>();
        if (j.contains("launch_at_login")) cfg.launch_at_login = j["launch_at_login"].get<bool>();
        if (j.contains("auto_connect_on_launch")) cfg.auto_connect_on_launch = j["auto_connect_on_launch"].get<bool>();
        if (j.contains("silent_startup")) cfg.silent_startup = j["silent_startup"].get<bool>();
        if (j.contains("connection_state_notifications")) cfg.connection_state_notifications = j["connection_state_notifications"].get<bool>();

        if (j.contains("password")) {
            std::string pw = j["password"].get<std::string>();
            if (!pw.empty() && cfg.remember_password) {
                crypto::init_key_if_needed();
                std::string ks = crypto::key_status();
                if (ks != "valid") {
                    return "Encryption key is " + ks + ". Reset key first.";
                }
                std::string encrypted = crypto::encrypt(pw, crypto::load_key());
                if (encrypted.empty()) {
                    return "Encryption failed";
                }
                cfg.password = encrypted;
                clear_stored_password = false;
            } else {
                clear_stored_password = true;
            }
        }
        if (clear_stored_password) {
            cfg.password.clear();
            cfg.remember_password = false;
        }
    } catch (const std::exception& e) {
        return std::string("Invalid config: ") + e.what();
    }

    normalize_native_only(cfg);
    if (!mgr.save(cfg)) {
        return "Failed to write config file. Check disk permissions for " +
               platform::get_config_path();
    }
    if (cfg.password.empty()) {
        crypto::delete_key_file();
    }
    exv::observability::LogFacade::info("Config imported via config_api");
    return "";
}

// ── Route management ──────────────────────────────────────────────

std::string route_add(config::ConfigManager& mgr, const std::string& cidr) {
    if (!is_valid_cidr(cidr)) {
        return "Invalid CIDR format: " + cidr;
    }

    Config cfg = mgr.load();
    if (std::find(cfg.routes.begin(), cfg.routes.end(), cidr) != cfg.routes.end()) {
        return "Route already exists: " + cidr;
    }

    cfg.routes.push_back(cidr);
    if (!mgr.save(cfg)) {
        return "Failed to write config file. Check disk permissions for " +
               platform::get_config_path();
    }
    exv::observability::LogFacade::info("Route added via config_api: " + cidr);
    return "";
}

std::string route_remove(config::ConfigManager& mgr, const std::string& cidr) {
    Config cfg = mgr.load();
    auto it = std::find(cfg.routes.begin(), cfg.routes.end(), cidr);
    if (it == cfg.routes.end()) {
        return "Route not found: " + cidr;
    }

    cfg.routes.erase(it);
    if (!mgr.save(cfg)) {
        return "Failed to write config file. Check disk permissions for " +
               platform::get_config_path();
    }
    exv::observability::LogFacade::info("Route removed via config_api: " + cidr);
    return "";
}

void route_reset_defaults(config::ConfigManager& mgr) {
    Config cfg = mgr.load();
    cfg.routes = Config{}.routes;
    mgr.save(cfg);
    exv::observability::LogFacade::info("Routes reset to defaults via config_api");
}

// ── Key management ────────────────────────────────────────────────

std::string key_status() {
    return crypto::key_status();
}

void key_reset_noninteractive() {
    std::string new_key = crypto::generate_key();
    if (!crypto::save_key(new_key)) {
        exv::observability::LogFacade::error("key_reset_noninteractive: failed to save new key");
        return;
    }

    // Clear password ciphertext in config.json
    std::string cfg_path = platform::get_config_path();
    if (platform::file_exists(cfg_path)) {
        std::string content = platform::read_file(cfg_path);
        try {
            auto j = nlohmann::json::parse(content);
            j["password"] = "";
            platform::write_file(cfg_path, j.dump(4));
        } catch (...) {
        }
    }

    exv::observability::LogFacade::info("Encryption key reset via config_api (non-interactive)");
}

} // namespace config_api
} // namespace exv
