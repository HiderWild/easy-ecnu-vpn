#include "core/use_cases/config_use_cases.hpp"

#include "core/config/config_api.hpp"
#include "core/crypto/crypto.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "platform/common/file_system.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_paths.hpp"
#include "platform/common/service_status.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace exv::core {
namespace {

using exv::Config;

constexpr std::string_view kProtectedExportFormat =
    "exv-config-protected-v1";
constexpr std::string_view kProtectedExportKdf =
    "exv-fnv1a64-rounds-v1";

nlohmann::json full_config_json(const Config &cfg);

std::string hex_from_bytes(const std::array<std::uint8_t, 32> &bytes) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4) & 0x0f]);
    out.push_back(kHex[byte & 0x0f]);
  }
  return out;
}

void fnv_mix(std::uint64_t &hash, std::string_view value) {
  constexpr std::uint64_t kPrime = 1099511628211ULL;
  for (unsigned char ch : value) {
    hash ^= static_cast<std::uint64_t>(ch);
    hash *= kPrime;
  }
}

void fnv_mix_u64(std::uint64_t &hash, std::uint64_t value) {
  char bytes[8];
  for (int i = 0; i < 8; ++i) {
    bytes[i] = static_cast<char>((value >> (i * 8)) & 0xff);
  }
  fnv_mix(hash, std::string_view(bytes, sizeof(bytes)));
}

std::string derive_protected_export_key(const std::string &password,
                                        const std::string &salt) {
  constexpr std::uint64_t kOffset = 1469598103934665603ULL;
  constexpr std::uint64_t kBlockSalt = 0x9e3779b97f4a7c15ULL;
  std::array<std::uint8_t, 32> key{};

  for (std::uint64_t block = 0; block < 4; ++block) {
    std::uint64_t hash = kOffset ^ (kBlockSalt * (block + 1));
    for (std::uint64_t round = 0; round < 8192; ++round) {
      fnv_mix(hash, password);
      fnv_mix_u64(hash, block);
      fnv_mix(hash, salt);
      fnv_mix_u64(hash, round);
      fnv_mix_u64(hash, hash >> 17);
    }
    for (int i = 0; i < 8; ++i) {
      key[static_cast<std::size_t>(block * 8 + i)] =
          static_cast<std::uint8_t>((hash >> (i * 8)) & 0xff);
    }
  }

  return hex_from_bytes(key);
}

nlohmann::json config_json_for_export(const Config &cfg,
                                      bool include_plaintext_password) {
  nlohmann::json export_json = full_config_json(cfg);
  if (!include_plaintext_password || cfg.password.empty() ||
      !cfg.remember_password) {
    export_json["password"] = "";
    export_json["password_stored"] = false;
    export_json["remember_password"] = false;
    return export_json;
  }

  const std::string key = exv::crypto::load_key();
  if (!exv::crypto::validate_key(key)) {
    return export_json;
  }

  const std::string plaintext = exv::crypto::decrypt(cfg.password, key);
  if (!plaintext.empty()) {
    export_json["password"] = plaintext;
  }
  return export_json;
}

nlohmann::json make_protected_export_envelope(
    const nlohmann::json &config_json, const std::string &password) {
  const std::string salt = exv::crypto::generate_key();
  if (!exv::crypto::validate_key(salt)) {
    return {};
  }

  const std::string derived_key = derive_protected_export_key(password, salt);
  nlohmann::json protected_payload = {
      {"magic", std::string(kProtectedExportFormat)},
      {"config", config_json},
  };
  const std::string ciphertext =
      exv::crypto::encrypt(protected_payload.dump(), derived_key);
  if (ciphertext.empty()) {
    return {};
  }

  return nlohmann::json{{"format", "protected"},
                        {"protected_format", std::string(kProtectedExportFormat)},
                        {"kdf", std::string(kProtectedExportKdf)},
                        {"salt", salt},
                        {"payload", ciphertext}};
}

std::optional<nlohmann::json>
decrypt_protected_export_envelope(const nlohmann::json &envelope,
                                  const std::string &password) {
  if (!envelope.is_object() ||
      envelope.value("format", std::string()) != "protected" ||
      envelope.value("protected_format", std::string()) !=
          std::string(kProtectedExportFormat) ||
      envelope.value("kdf", std::string()) !=
          std::string(kProtectedExportKdf) ||
      !envelope.contains("salt") || !envelope["salt"].is_string() ||
      !envelope.contains("payload") || !envelope["payload"].is_string()) {
    return std::nullopt;
  }

  const std::string derived_key = derive_protected_export_key(
      password, envelope["salt"].get<std::string>());
  const std::string plaintext =
      exv::crypto::decrypt(envelope["payload"].get<std::string>(), derived_key);
  if (plaintext.empty()) {
    return std::nullopt;
  }

  try {
    auto wrapper = nlohmann::json::parse(plaintext);
    if (!wrapper.is_object() ||
        wrapper.value("magic", std::string()) !=
            std::string(kProtectedExportFormat) ||
        !wrapper.contains("config") || !wrapper["config"].is_object()) {
      return std::nullopt;
    }
    return wrapper["config"];
  } catch (...) {
    return std::nullopt;
  }
}

nlohmann::json auth_json(const Config &cfg) {
  return nlohmann::json{{"server", cfg.server},
                        {"username", cfg.username},
                        {"password", ""},
                        {"password_stored", !cfg.password.empty()},
                        {"user_agent", cfg.useragent},
                        {"remember_password", cfg.remember_password}};
}

nlohmann::json settings_json(const Config &cfg) {
  std::string extra_args;
  for (std::size_t i = 0; i < cfg.extra_args.size(); ++i) {
    if (i > 0) {
      extra_args += " ";
    }
    extra_args += cfg.extra_args[i];
  }

  return nlohmann::json{{"mtu", cfg.mtu},
                        {"dtls", !cfg.disable_dtls},
                        {"dtls_mode", cfg.dtls_mode},
                        {"extra_args", extra_args},
                        {"log_path", cfg.log_file},
                        {"vpn_engine", cfg.vpn_engine},
                        {"windows_tunnel_driver", cfg.windows_tunnel_driver},
                        {"windows_tap_interface", cfg.windows_tap_interface},
                        {"auto_reconnect", cfg.auto_reconnect},
                        {"retry_limit", cfg.retry_limit},
                        {"minimal_mode", cfg.minimal_mode},
                        {"service_install_prompt_seen",
                         cfg.service_install_prompt_seen},
                        {"minimal_install_service_before_connect",
                         cfg.minimal_install_service_before_connect},
                        {"include_class_a_private_routes",
                         cfg.include_class_a_private_routes},
                        {"include_class_b_private_routes",
                         cfg.include_class_b_private_routes},
                        {"launch_at_login", cfg.launch_at_login},
                        {"auto_connect_on_launch",
                         cfg.auto_connect_on_launch},
                        {"silent_startup", cfg.silent_startup},
                        {"connection_state_notifications",
                         cfg.connection_state_notifications}};
}

nlohmann::json full_config_json(const Config &cfg) {
  nlohmann::json config = cfg;
  config["password"] = "";
  config["password_stored"] = !cfg.password.empty();
  return config;
}

nlohmann::json route_array_json(const Config &cfg) {
  nlohmann::json routes = nlohmann::json::array();
  for (const auto &route : cfg.routes) {
    routes.push_back({{"cidr", route},
                      {"destination", route},
                      {"enabled", true}});
  }
  return routes;
}

const nlohmann::json &settings_payload(const nlohmann::json &payload) {
  if (payload.contains("settings") && payload["settings"].is_object()) {
    return payload["settings"];
  }
  if (payload.contains("config") && payload["config"].is_object()) {
    return payload["config"];
  }
  return payload;
}

std::string bool_value(bool value) { return value ? "true" : "false"; }

UseCaseResult error_from_config_api(const std::string &message) {
  if (message.find("not found") != std::string::npos ||
      message.find("Not found") != std::string::npos) {
    return UseCaseResult::fail("not_found", message);
  }
  if (message.find("already exists") != std::string::npos) {
    return UseCaseResult::fail("already_exists", message);
  }
  return UseCaseResult::fail("invalid_payload", message);
}

std::string trim_copy(std::string value) {
  auto is_not_space = [](unsigned char ch) {
    return std::isspace(ch) == 0;
  };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
                                          is_not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), is_not_space).base(),
              value.end());
  return value;
}

std::string lowercase_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

std::filesystem::path frontend_executable_path() {
  namespace fs = std::filesystem;
  fs::path current(exv::platform::get_executable_path());
  if (current.empty()) {
    return current;
  }

  std::vector<fs::path> candidates;
  const std::string filename = lowercase_copy(current.filename().string());
#ifdef _WIN32
  if (filename == "exv-ui.exe") {
    candidates.push_back(current);
  }
  candidates.push_back(current.parent_path() / "exv-ui.exe");
  candidates.push_back(current.parent_path().parent_path() / "exv-ui.exe");
#else
  if (filename == "exv-ui") {
    candidates.push_back(current);
  }
  candidates.push_back(current.parent_path() / "exv-ui");
  candidates.push_back(current.parent_path().parent_path() / "exv-ui");
#endif
  candidates.push_back(current);

  std::error_code ec;
  for (const auto &candidate : candidates) {
    if (!candidate.empty() && fs::exists(candidate, ec)) {
      return candidate;
    }
    ec.clear();
  }
  return current;
}

std::vector<std::string>
frontend_launch_arguments(const std::filesystem::path &frontend_executable) {
  namespace fs = std::filesystem;
  std::vector<std::string> args;
  const fs::path package_root = frontend_executable.parent_path();
  const fs::path args_path = package_root / "exv-ui.args";
  std::error_code ec;
  if (!fs::exists(args_path, ec)) {
    return args;
  }

  std::ifstream in(args_path);
  std::string line;
  while (std::getline(in, line)) {
    line = trim_copy(line);
    if (line.empty() || line[0] == '#') {
      continue;
    }
    if (line.rfind("--", 0) != 0) {
      fs::path target(line);
      if (target.is_relative()) {
        line = (package_root / target).string();
      }
    }
    args.push_back(line);
  }
  return args;
}

#ifdef _WIN32
std::wstring wide_from_utf8(const std::string &value) {
  if (value.empty()) {
    return {};
  }
  int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     value.c_str(), -1, nullptr, 0);
  UINT code_page = CP_UTF8;
  DWORD flags = MB_ERR_INVALID_CHARS;
  if (required <= 0) {
    code_page = CP_ACP;
    flags = 0;
    required = MultiByteToWideChar(code_page, flags, value.c_str(), -1,
                                   nullptr, 0);
  }
  if (required <= 0) {
    return {};
  }
  std::wstring out(static_cast<std::size_t>(required), L'\0');
  MultiByteToWideChar(code_page, flags, value.c_str(), -1, out.data(),
                      required);
  if (!out.empty() && out.back() == L'\0') {
    out.pop_back();
  }
  return out;
}

std::wstring quote_windows_arg(const std::wstring &arg) {
  std::wstring out = L"\"";
  for (wchar_t ch : arg) {
    if (ch == L'"') {
      out += L'\\';
    }
    out += ch;
  }
  out += L'"';
  return out;
}

std::wstring windows_autostart_command() {
  const auto frontend = frontend_executable_path();
  if (frontend.empty()) {
    return {};
  }
  std::wstring command = quote_windows_arg(frontend.wstring());
  for (const auto &arg : frontend_launch_arguments(frontend)) {
    command += L' ';
    command += quote_windows_arg(wide_from_utf8(arg));
  }
  return command;
}
#endif

std::string xml_escape(std::string value) {
  std::string out;
  out.reserve(value.size());
  for (char ch : value) {
    switch (ch) {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    case '\'':
      out += "&apos;";
      break;
    default:
      out += ch;
      break;
    }
  }
  return out;
}

std::string launch_home_dir() {
  std::string home = exv::platform::get_effective_home();
  if (!home.empty()) {
    return home;
  }
  const char *env_home = std::getenv("HOME");
  return env_home ? std::string(env_home) : std::string();
}

UseCaseResult apply_launch_at_login(bool enabled) {
#ifdef _WIN32
  constexpr const wchar_t *kRunKey =
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
  constexpr const wchar_t *kValueName = L"EXV VPN Client";
  HKEY key = nullptr;
  if (!enabled) {
    LONG open_result =
        RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE, &key);
    if (open_result == ERROR_FILE_NOT_FOUND) {
      return UseCaseResult::ok();
    }
    if (open_result != ERROR_SUCCESS) {
      return UseCaseResult::fail("system_operation_failed",
                                 "Failed to open Windows Run registry key.");
    }
    LONG delete_result = RegDeleteValueW(key, kValueName);
    RegCloseKey(key);
    if (delete_result == ERROR_SUCCESS ||
        delete_result == ERROR_FILE_NOT_FOUND) {
      return UseCaseResult::ok();
    }
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to remove Windows login item.");
  }

  const std::wstring command = windows_autostart_command();
  if (command.empty()) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to resolve EXV UI executable.");
  }
  LONG create_result = RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr,
                                       0, KEY_SET_VALUE, nullptr, &key,
                                       nullptr);
  if (create_result != ERROR_SUCCESS) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to create Windows Run registry key.");
  }
  const DWORD byte_count =
      static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t));
  LONG set_result = RegSetValueExW(
      key, kValueName, 0, REG_SZ,
      reinterpret_cast<const BYTE *>(command.c_str()), byte_count);
  RegCloseKey(key);
  if (set_result != ERROR_SUCCESS) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to write Windows login item.");
  }
  return UseCaseResult::ok();
#elif defined(__APPLE__)
  namespace fs = std::filesystem;
  const std::string home = launch_home_dir();
  if (home.empty()) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to resolve user home directory.");
  }
  const fs::path agents_dir = fs::path(home) / "Library" / "LaunchAgents";
  const fs::path plist_path = agents_dir / "cn.edu.ecnu.exv.plist";
  std::error_code ec;
  if (!enabled) {
    fs::remove(plist_path, ec);
    return UseCaseResult::ok();
  }

  fs::create_directories(agents_dir, ec);
  if (ec) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to create LaunchAgents directory.");
  }
  const auto frontend = frontend_executable_path();
  std::vector<std::string> args;
  args.push_back(frontend.string());
  for (const auto &arg : frontend_launch_arguments(frontend)) {
    args.push_back(arg);
  }

  std::ofstream out(plist_path);
  if (!out) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to write macOS login item.");
  }
  out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
      << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
      << "<plist version=\"1.0\">\n"
      << "<dict>\n"
      << "  <key>Label</key><string>cn.edu.ecnu.exv</string>\n"
      << "  <key>ProgramArguments</key>\n"
      << "  <array>\n";
  for (const auto &arg : args) {
    out << "    <string>" << xml_escape(arg) << "</string>\n";
  }
  out << "  </array>\n"
      << "  <key>RunAtLoad</key><true/>\n"
      << "</dict>\n"
      << "</plist>\n";
  return UseCaseResult::ok();
#else
  namespace fs = std::filesystem;
  const std::string home = launch_home_dir();
  if (home.empty()) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to resolve user home directory.");
  }
  const fs::path autostart_dir = fs::path(home) / ".config" / "autostart";
  const fs::path desktop_path = autostart_dir / "exv-vpn-client.desktop";
  std::error_code ec;
  if (!enabled) {
    fs::remove(desktop_path, ec);
    return UseCaseResult::ok();
  }
  fs::create_directories(autostart_dir, ec);
  if (ec) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to create autostart directory.");
  }
  const auto frontend = frontend_executable_path();
  std::string exec = "\"" + frontend.string() + "\"";
  for (const auto &arg : frontend_launch_arguments(frontend)) {
    exec += " \"" + arg + "\"";
  }
  std::ofstream out(desktop_path);
  if (!out) {
    return UseCaseResult::fail("system_operation_failed",
                               "Failed to write autostart desktop file.");
  }
  out << "[Desktop Entry]\n"
      << "Type=Application\n"
      << "Name=EXV VPN Client\n"
      << "Exec=" << exec << "\n"
      << "Terminal=false\n"
      << "X-GNOME-Autostart-enabled=true\n";
  return UseCaseResult::ok();
#endif
}

bool remembered_password_ready(const Config &cfg) {
  return cfg.remember_password && !trim_copy(cfg.username).empty() &&
         !cfg.password.empty();
}

UseCaseResult validate_settings_business_rules_before_save(
    const Config &current, const nlohmann::json &settings) {
  if (settings.contains("auto_connect_on_launch") &&
      settings["auto_connect_on_launch"].is_boolean() &&
      settings["auto_connect_on_launch"].get<bool>()) {
    if (!remembered_password_ready(current)) {
      return UseCaseResult::fail(
          "invalid_payload",
          "auto_connect_on_launch requires a remembered password.");
    }
    if (!exv::platform::current_service_status().installed) {
      return UseCaseResult::fail(
          "invalid_payload",
          "auto_connect_on_launch requires an installed helper service.");
    }
  }
  return UseCaseResult::ok();
}

UseCaseResult validate_auth_payload_before_save(const Config &current,
                                                const nlohmann::json &payload) {
  std::string next_username = trim_copy(current.username);
  if (payload.contains("username") && payload["username"].is_string()) {
    next_username = trim_copy(payload["username"].get<std::string>());
  }

  const bool has_submitted_password =
      payload.contains("password") && payload["password"].is_string() &&
      !payload["password"].get<std::string>().empty();
  const bool enables_remember_password =
      payload.contains("remember_password") &&
      payload["remember_password"].is_boolean() &&
      payload["remember_password"].get<bool>();

  if (next_username.empty() &&
      (has_submitted_password || enables_remember_password)) {
    return UseCaseResult::fail(
        "invalid_payload",
        "username is required before saving a remembered password.");
  }

  return UseCaseResult::ok();
}

UseCaseResult validate_settings_payload_before_save(
    const nlohmann::json &settings) {
  auto type_error = [](const std::string &field, const std::string &type) {
    return UseCaseResult::fail("invalid_payload",
                               field + " must be " + type + ".");
  };

  auto validate_bool = [&](const char *field) -> UseCaseResult {
    if (settings.contains(field) && !settings[field].is_boolean()) {
      return type_error(field, "a boolean");
    }
    return UseCaseResult::ok();
  };

  auto validate_string = [&](const char *field) -> UseCaseResult {
    if (settings.contains(field) && !settings[field].is_string()) {
      return type_error(field, "a string");
    }
    return UseCaseResult::ok();
  };

  if (settings.contains("mtu")) {
    if (!settings["mtu"].is_number_integer()) {
      return type_error("mtu", "an integer");
    }
    const int mtu = settings["mtu"].get<int>();
    if (mtu < 576 || mtu > 1500) {
      return UseCaseResult::fail("invalid_payload",
                                 "mtu must be between 576 and 1500.");
    }
  }

  if (settings.contains("retry_limit")) {
    if (!settings["retry_limit"].is_number_integer()) {
      return type_error("retry_limit", "an integer");
    }
    if (settings["retry_limit"].get<int>() < 0) {
      return UseCaseResult::fail(
          "invalid_payload",
          "retry_limit must be 0 or a positive integer.");
    }
  }

  if (settings.contains("extra_args")) {
    if (settings["extra_args"].is_array()) {
      for (const auto &arg : settings["extra_args"]) {
        if (!arg.is_string()) {
          return type_error("extra_args", "a string or string array");
        }
      }
    } else if (!settings["extra_args"].is_string()) {
      return type_error("extra_args", "a string or string array");
    }
  }

  for (UseCaseResult result :
       {validate_bool("dtls"), validate_bool("disable_dtls"),
       validate_bool("auto_reconnect"), validate_bool("minimal_mode"),
        validate_bool("service_install_prompt_seen"),
        validate_bool("minimal_install_service_before_connect"),
        validate_bool("include_class_a_private_routes"),
        validate_bool("include_class_b_private_routes"),
        validate_bool("launch_at_login"),
        validate_bool("auto_connect_on_launch"),
        validate_bool("silent_startup"),
        validate_bool("connection_state_notifications"),
        validate_string("log_path"), validate_string("log_file"),
        validate_string("dtls_mode"),
        validate_string("vpn_engine"),
        validate_string("windows_tunnel_driver"),
        validate_string("windows_tap_interface")}) {
    if (!result.success) {
      return result;
    }
  }

  if (settings.contains("vpn_engine") &&
      settings["vpn_engine"].get<std::string>() != "native") {
    return UseCaseResult::fail(
        "invalid_payload",
        "vpn_engine is native-only; legacy engine has been removed.");
  }

  if (settings.contains("dtls_mode")) {
    const std::string mode = settings["dtls_mode"].get<std::string>();
    if (mode != "auto" && mode != "enabled" && mode != "disabled") {
      return UseCaseResult::fail(
          "invalid_payload",
          "dtls_mode must be auto, enabled, or disabled.");
    }
  }

  if (settings.contains("windows_tunnel_driver")) {
    const std::string driver =
        settings["windows_tunnel_driver"].get<std::string>();
    if (driver != "auto" && driver != "wintun" && driver != "tap") {
      return UseCaseResult::fail(
          "invalid_payload",
          "windows_tunnel_driver must be auto, wintun, or tap.");
    }
  }

  return UseCaseResult::ok();
}

std::string route_cidr_from_payload(const nlohmann::json &payload) {
  if (payload.contains("cidr") && payload["cidr"].is_string()) {
    return payload["cidr"].get<std::string>();
  }
  if (payload.contains("destination") && payload["destination"].is_string()) {
    return payload["destination"].get<std::string>();
  }
  return "";
}

} // namespace

ConfigUseCases::ConfigUseCases()
    : ConfigUseCases(exv::platform::get_config_dir()) {}

ConfigUseCases::ConfigUseCases(std::string config_dir)
    : manager_(std::move(config_dir)) {
  exv::platform::logging::configure_default_logging(false);
}

Config ConfigUseCases::load_config() { return manager_.load(); }

UseCaseResult ConfigUseCases::get_config() {
  Config cfg = manager_.load();
  return UseCaseResult::ok({{"config", full_config_json(cfg)},
                            {"auth", auth_json(cfg)},
                            {"settings", settings_json(cfg)},
                            {"routes", route_array_json(cfg)}});
}

UseCaseResult ConfigUseCases::save_config(const nlohmann::json &payload) {
  UseCaseResult auth = save_auth(payload);
  if (!auth.success) {
    return auth;
  }
  return save_settings(payload);
}

UseCaseResult ConfigUseCases::get_profile(const nlohmann::json &payload) {
  if (!payload.contains("profile_id") || !payload["profile_id"].is_string()) {
    return UseCaseResult::fail("invalid_payload", "profile_id is required");
  }
  return UseCaseResult::fail(
      "unsupported_action",
      "Named config profiles are not supported by the current config model.");
}

UseCaseResult ConfigUseCases::save_profile(const nlohmann::json &payload) {
  if (!payload.contains("profile_id") || !payload["profile_id"].is_string()) {
    return UseCaseResult::fail("invalid_payload", "profile_id is required");
  }
  return UseCaseResult::fail(
      "unsupported_action",
      "Named config profiles are not supported by the current config model.");
}

UseCaseResult ConfigUseCases::get_auth() {
  return UseCaseResult::ok(auth_json(manager_.load()));
}

UseCaseResult ConfigUseCases::save_auth(const nlohmann::json &payload) {
  Config current = manager_.load();
  UseCaseResult validation = validate_auth_payload_before_save(current, payload);
  if (!validation.success) {
    return validation;
  }

  if (payload.contains("server") && payload["server"].is_string()) {
    std::string err = exv::config_api::config_set(
        manager_, "server", payload["server"].get<std::string>());
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (payload.contains("username") && payload["username"].is_string()) {
    std::string err = exv::config_api::config_set(
        manager_, "username", payload["username"].get<std::string>());
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (payload.contains("user_agent") && payload["user_agent"].is_string()) {
    const std::string user_agent = payload["user_agent"].get<std::string>();
    if (!user_agent.empty()) {
      std::string err =
          exv::config_api::config_set(manager_, "useragent", user_agent);
      if (!err.empty()) {
        return error_from_config_api(err);
      }
    }
  }
  const bool has_submitted_password =
      payload.contains("password") && payload["password"].is_string() &&
      !payload["password"].get<std::string>().empty();
  if (payload.contains("remember_password") &&
      payload["remember_password"].is_boolean()) {
    const bool remember = payload["remember_password"].get<bool>();
    if (!remember) {
      std::string err =
          exv::config_api::config_clear_password_and_key(manager_);
      if (!err.empty()) {
        return error_from_config_api(err);
      }
    } else {
      if (!has_submitted_password && current.password.empty()) {
        return UseCaseResult::fail(
            "invalid_payload",
            "Password is required to enable remember_password.");
      }
      std::string err = exv::config_api::config_set(
          manager_, "remember_password", "true");
      if (!err.empty()) {
        return error_from_config_api(err);
      }
    }
  }
  if (has_submitted_password) {
    std::string err = exv::config_api::config_set_password(
        manager_, payload["password"].get<std::string>());
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  return get_auth();
}

UseCaseResult ConfigUseCases::get_settings() {
  return UseCaseResult::ok(settings_json(manager_.load()));
}

UseCaseResult ConfigUseCases::save_settings(const nlohmann::json &payload) {
  const nlohmann::json &settings = settings_payload(payload);
  UseCaseResult validation = validate_settings_payload_before_save(settings);
  if (!validation.success) {
    return validation;
  }
  Config current = manager_.load();
  UseCaseResult business_validation =
      validate_settings_business_rules_before_save(current, settings);
  if (!business_validation.success) {
    return business_validation;
  }
  if (settings.contains("launch_at_login") &&
      settings["launch_at_login"].is_boolean()) {
    UseCaseResult launch_result =
        apply_launch_at_login(settings["launch_at_login"].get<bool>());
    if (!launch_result.success) {
      return launch_result;
    }
  }

  auto set_string = [&](const char *json_key, const char *config_key)
      -> UseCaseResult {
    if (settings.contains(json_key) && settings[json_key].is_string()) {
      std::string err = exv::config_api::config_set(
          manager_, config_key, settings[json_key].get<std::string>());
      if (!err.empty()) {
        return error_from_config_api(err);
      }
    }
    return UseCaseResult::ok();
  };

  auto set_bool = [&](const char *json_key, const char *config_key)
      -> UseCaseResult {
    if (settings.contains(json_key) && settings[json_key].is_boolean()) {
      std::string err = exv::config_api::config_set(
          manager_, config_key, bool_value(settings[json_key].get<bool>()));
      if (!err.empty()) {
        return error_from_config_api(err);
      }
    }
    return UseCaseResult::ok();
  };

  if (settings.contains("mtu") && settings["mtu"].is_number_integer()) {
    std::string err = exv::config_api::config_set(
        manager_, "mtu", std::to_string(settings["mtu"].get<int>()));
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (settings.contains("dtls") && settings["dtls"].is_boolean()) {
    std::string err = exv::config_api::config_set(
        manager_, "disable_dtls", settings["dtls"].get<bool>() ? "false"
                                                               : "true");
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (settings.contains("disable_dtls") &&
      settings["disable_dtls"].is_boolean()) {
    std::string err = exv::config_api::config_set(
        manager_, "disable_dtls",
        bool_value(settings["disable_dtls"].get<bool>()));
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (settings.contains("dtls_mode") && settings["dtls_mode"].is_string()) {
    std::string err = exv::config_api::config_set(
        manager_, "dtls_mode", settings["dtls_mode"].get<std::string>());
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (settings.contains("retry_limit") &&
      settings["retry_limit"].is_number_integer()) {
    std::string err = exv::config_api::config_set(
        manager_, "retry_limit",
        std::to_string(settings["retry_limit"].get<int>()));
    if (!err.empty()) {
      return error_from_config_api(err);
    }
  }
  if (settings.contains("extra_args")) {
    Config updated = manager_.load();
    if (settings["extra_args"].is_array()) {
      updated.extra_args = settings["extra_args"].get<std::vector<std::string>>();
    } else if (settings["extra_args"].is_string()) {
      const std::string value = settings["extra_args"].get<std::string>();
      updated.extra_args =
          value.empty() ? std::vector<std::string>{}
                        : std::vector<std::string>{value};
    } else {
      return UseCaseResult::fail("invalid_payload",
                                 "extra_args must be a string or array");
    }
    if (!manager_.save(updated)) {
      return UseCaseResult::fail("config_save_failed",
                                 "Failed to write config file.");
    }
  }

  for (UseCaseResult result :
       {set_string("log_path", "log_file"),
        set_string("log_file", "log_file"),
        set_string("vpn_engine", "vpn_engine"),
        set_string("windows_tunnel_driver", "windows_tunnel_driver"),
        set_string("windows_tap_interface", "windows_tap_interface"),
        set_bool("auto_reconnect", "auto_reconnect"),
        set_bool("minimal_mode", "minimal_mode"),
        set_bool("service_install_prompt_seen",
                 "service_install_prompt_seen"),
        set_bool("minimal_install_service_before_connect",
                 "minimal_install_service_before_connect"),
        set_bool("include_class_a_private_routes",
                 "include_class_a_private_routes"),
        set_bool("include_class_b_private_routes",
                 "include_class_b_private_routes"),
        set_bool("launch_at_login", "launch_at_login"),
        set_bool("auto_connect_on_launch", "auto_connect_on_launch"),
        set_bool("silent_startup", "silent_startup"),
        set_bool("connection_state_notifications",
                 "connection_state_notifications")}) {
    if (!result.success) {
      return result;
    }
  }

  Config cfg = manager_.load();
  return UseCaseResult::ok({{"saved", true},
                            {"config", full_config_json(cfg)},
                            {"settings", settings_json(cfg)}});
}

UseCaseResult ConfigUseCases::get_key_status() {
  const std::string status = exv::config_api::key_status();
  return UseCaseResult::ok(
      {{"present", status == "valid"},
       {"fingerprint", status == "valid" ? nlohmann::json("active")
                                         : nlohmann::json(nullptr)},
       {"status", status}});
}

UseCaseResult ConfigUseCases::list_routes() {
  return UseCaseResult::ok({{"routes", route_array_json(manager_.load())}});
}

UseCaseResult ConfigUseCases::add_route(const nlohmann::json &payload) {
  const std::string cidr = route_cidr_from_payload(payload);
  if (cidr.empty()) {
    return UseCaseResult::fail("invalid_payload",
                               "cidr or destination is required");
  }
  std::string err = exv::config_api::route_add(manager_, cidr);
  if (!err.empty()) {
    return error_from_config_api(err);
  }
  return UseCaseResult::ok(
      {{"added", true}, {"routes", route_array_json(manager_.load())}});
}

UseCaseResult ConfigUseCases::remove_route(const nlohmann::json &payload) {
  const std::string cidr = route_cidr_from_payload(payload);
  if (cidr.empty()) {
    return UseCaseResult::fail("invalid_payload",
                               "cidr or destination is required");
  }
  std::string err = exv::config_api::route_remove(manager_, cidr);
  if (!err.empty()) {
    return error_from_config_api(err);
  }
  return UseCaseResult::ok(
      {{"removed", true}, {"routes", route_array_json(manager_.load())}});
}

UseCaseResult ConfigUseCases::reset_routes() {
  exv::config_api::route_reset_defaults(manager_);
  return UseCaseResult::ok(
      {{"reset", true}, {"routes", route_array_json(manager_.load())}});
}

UseCaseResult ConfigUseCases::route_enable_unsupported() {
  return UseCaseResult::fail(
      "unsupported_action",
      "Persisted route enablement is not supported by the config model.");
}

UseCaseResult ConfigUseCases::route_disable_unsupported() {
  return UseCaseResult::fail(
      "unsupported_action",
      "Persisted route disablement is not supported by the config model.");
}

UseCaseResult ConfigUseCases::reset_config() {
  UseCaseResult launch_result = apply_launch_at_login(false);
  if (!launch_result.success) {
    return launch_result;
  }
  exv::config_api::config_reset(manager_);
  Config cfg = manager_.load();
  return UseCaseResult::ok({{"reset", true},
                            {"config", full_config_json(cfg)},
                            {"settings", settings_json(cfg)},
                            {"routes", route_array_json(cfg)}});
}

UseCaseResult ConfigUseCases::reset_key() {
  exv::config_api::key_reset_noninteractive();
  return UseCaseResult::ok({{"reset", true},
                            {"key", {{"status", "reset"}}}});
}

UseCaseResult ConfigUseCases::import_config(const nlohmann::json &payload) {
  const std::string protected_import_error =
      "无法解密或读取受保护的配置文件。可能原因包括：导入口令不正确、文件已损坏、文件内容被修改，或配置格式不兼容。";
  const std::string invalid_import_error =
      "导入文件不是有效的 EXV 配置文件。可能原因包括：文件已损坏、内容不完整，或配置格式不兼容。";
  const bool requested_protected =
      payload.value("format", std::string()) == "protected";
  if (requested_protected &&
      (!payload.contains("password") || !payload["password"].is_string() ||
       trim_copy(payload["password"].get<std::string>()).empty())) {
    return UseCaseResult::fail("config_import_auth_failed",
                               "导入口令是必填项。");
  }

  // Import can take either a direct config object or a nested "config" field
  nlohmann::json config_json;
  if (payload.contains("data") && payload["data"].is_string()) {
    try {
      config_json = nlohmann::json::parse(payload["data"].get<std::string>());
    } catch (const std::exception &e) {
      (void)e;
      return UseCaseResult::fail("invalid_config", invalid_import_error);
    }
  } else if (payload.contains("config") && payload["config"].is_object()) {
    config_json = payload["config"];
  } else if (payload.contains("import_data") && payload["import_data"].is_object()) {
    config_json = payload["import_data"];
  } else {
    config_json = payload;
  }

  for (int unwrap_depth = 0; unwrap_depth < 2; ++unwrap_depth) {
    if (config_json.is_object() && config_json.contains("export_data") &&
        config_json["export_data"].is_object()) {
      config_json = config_json["export_data"];
      continue;
    }
    if (config_json.is_object() && config_json.contains("data") &&
        config_json["data"].is_string()) {
      const std::string format = config_json.value("format", std::string());
      if (format == "protected" || format == "unprotected") {
        try {
          config_json =
              nlohmann::json::parse(config_json["data"].get<std::string>());
        } catch (const std::exception &e) {
          (void)e;
          return UseCaseResult::fail(
              format == "protected"
                  ? "config_import_tampered_or_wrong_password"
                  : "invalid_config",
              format == "protected" ? protected_import_error
                                    : invalid_import_error);
        }
        continue;
      }
    }
    break;
  }

  const bool data_is_protected =
      config_json.is_object() &&
      config_json.value("format", std::string()) == "protected";
  if (requested_protected || data_is_protected) {
    if (!payload.contains("password") || !payload["password"].is_string() ||
        trim_copy(payload["password"].get<std::string>()).empty()) {
      return UseCaseResult::fail("config_import_auth_failed",
                                 "导入口令是必填项。");
    }
    auto decrypted = decrypt_protected_export_envelope(
        config_json, payload["password"].get<std::string>());
    if (!decrypted.has_value()) {
      return UseCaseResult::fail(
          "config_import_tampered_or_wrong_password", protected_import_error);
    }
    config_json = *decrypted;
  }

  Config current = manager_.load();
  UseCaseResult auth_validation =
      validate_auth_payload_before_save(current, config_json);
  if (!auth_validation.success) {
    return UseCaseResult::fail("invalid_config",
                               auth_validation.error_message);
  }
  UseCaseResult settings_validation =
      validate_settings_payload_before_save(config_json);
  if (!settings_validation.success) {
    return UseCaseResult::fail("invalid_config",
                               settings_validation.error_message);
  }

  // Convert JSON to string for config_import
  std::string json_str = config_json.dump();
  std::string err = exv::config_api::config_import(manager_, json_str);
  if (!err.empty()) {
    // Check error type and choose appropriate error code
    if (err.find("tampered") != std::string::npos || err.find("password") != std::string::npos) {
      return UseCaseResult::fail("config_import_tampered_or_wrong_password", err);
    }
    if (err.find("unsupported") != std::string::npos) {
      return UseCaseResult::fail("config_import_format_unsupported", err);
    }
    return UseCaseResult::fail("invalid_config", err);
  }

  Config cfg = manager_.load();
  return UseCaseResult::ok({{"imported", true},
                            {"config", full_config_json(cfg)},
                            {"settings", settings_json(cfg)},
                            {"routes", route_array_json(cfg)}});
}

UseCaseResult ConfigUseCases::export_config(const nlohmann::json &payload) {
  Config cfg = manager_.load();

  // Export format - clean config object without sensitive data
  if (payload.contains("protected") && !payload["protected"].is_boolean()) {
    return UseCaseResult::fail("invalid_payload",
                               "protected must be a boolean.");
  }
  if (payload.contains("password") && !payload["password"].is_string()) {
    return UseCaseResult::fail("invalid_payload",
                               "password must be a string.");
  }
  const bool protected_export = payload.value("protected", false);
  const std::string export_password =
      payload.contains("password") && payload["password"].is_string()
          ? payload["password"].get<std::string>()
          : std::string();
  if (protected_export) {
    if (!payload.contains("password") || !payload["password"].is_string() ||
        trim_copy(export_password).empty()) {
      return UseCaseResult::fail("invalid_payload",
                                 "Export password is required.");
    }
    if (cfg.remember_password && !cfg.password.empty() &&
        !exv::crypto::validate_key(exv::crypto::load_key())) {
      return UseCaseResult::fail(
          "credential_store_unavailable",
          "Saved VPN password cannot be exported because the local key is unavailable.");
    }
  }

  nlohmann::json export_json = config_json_for_export(cfg, protected_export);
  if (protected_export && cfg.remember_password && !cfg.password.empty() &&
      export_json.value("password", std::string()).empty()) {
    return UseCaseResult::fail(
        "credential_store_unavailable",
        "Saved VPN password could not be decrypted for export.");
  }

  // Add export metadata
  export_json["export_version"] = "1.0";
  export_json["exported_at"] = ""; // Could be set with timestamp if needed
  export_json["protected"] = protected_export;

  if (protected_export) {
    nlohmann::json envelope =
        make_protected_export_envelope(export_json, export_password);
    if (envelope.empty()) {
      return UseCaseResult::fail("invalid_payload",
                                 "Failed to create protected export.");
    }
    return UseCaseResult::ok({{"exported", true},
                              {"format", "protected"},
                              {"data", envelope.dump(2)},
                              {"export_data", envelope}});
  }

  return UseCaseResult::ok({{"exported", true},
                            {"format", "unprotected"},
                            {"data", export_json.dump(2)},
                            {"export_data", export_json}});
}

} // namespace exv::core
