#include "core/tunnel_controller/native_engine_config_mapper.hpp"

#include <sstream>
#include <utility>
#include <vector>

namespace exv::core {
namespace {

exv::vpn_engine::ValidationResult invalid(std::string code,
                                              std::string message) {
  exv::vpn_engine::ValidationResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

struct NativeExtraArgs {
  bool no_dtls = false;
  std::string useragent;
  std::string auth_group;
  std::string csd_wrapper;
};

bool contains_header_control_char(const std::string &value) {
  for (unsigned char ch : value) {
    if (ch == '\r' || ch == '\n' || ch == '\0')
      return true;
  }
  return false;
}

std::string argument_name(const std::string &arg) {
  const std::size_t eq = arg.find('=');
  if (eq != std::string::npos)
    return arg.substr(0, eq);
  if (arg.rfind("--", 0) == 0)
    return arg;
  return "<value>";
}

std::string join_argument_names(const std::vector<std::string> &names) {
  std::ostringstream out;
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i > 0)
      out << ", ";
    out << names[i];
  }
  return out.str();
}

bool split_inline_value(const std::string &arg, const char *prefix,
                        std::string *value) {
  const std::string key(prefix);
  if (arg.rfind(key, 0) != 0)
    return false;
  if (arg.size() <= key.size() || arg[key.size()] != '=')
    return false;
  if (value)
    *value = arg.substr(key.size() + 1);
  return true;
}

exv::vpn_engine::ValidationResult
parse_native_extra_args(const std::vector<std::string> &args,
                        NativeExtraArgs *out) {
  if (!out)
    return invalid("invalid_output", "Native extra_args output pointer is null.");

  NativeExtraArgs parsed;
  std::vector<std::string> unsupported;

  for (const std::string &arg : args) {
    std::string value;
    if (arg == "--no-dtls") {
      parsed.no_dtls = true;
    } else if (split_inline_value(arg, "--useragent", &value)) {
      if (value.empty() || contains_header_control_char(value)) {
        return invalid("config_invalid",
                       "Native --useragent value is empty or invalid.");
      }
      parsed.useragent = std::move(value);
    } else if (split_inline_value(arg, "--authgroup", &value)) {
      if (value.empty())
        return invalid("config_invalid", "Native --authgroup value is empty.");
      parsed.auth_group = std::move(value);
    } else if (split_inline_value(arg, "--csd-wrapper", &value)) {
      if (value.empty())
        return invalid("config_invalid", "Native --csd-wrapper value is empty.");
      parsed.csd_wrapper = std::move(value);
    } else {
      unsupported.push_back(argument_name(arg));
    }
  }

  if (!unsupported.empty()) {
    return invalid("unsupported_extra_args",
                   "Unsupported native extra_args: " +
                       join_argument_names(unsupported));
  }

  *out = std::move(parsed);
  return {};
}

} // namespace

exv::vpn_engine::ValidationResult
validate_native_app_config(const exv::Config &cfg) {
  NativeExtraArgs extra;
  auto extra_result = parse_native_extra_args(cfg.extra_args, &extra);
  if (!extra_result.ok)
    return extra_result;
  if (cfg.server.empty()) {
    return invalid("config_invalid", "VPN server is not configured.");
  }
  if (cfg.username.empty()) {
    return invalid("config_invalid", "VPN username is not configured.");
  }
  return exv::vpn_engine::ValidationResult{};
}

exv::vpn_engine::ValidationResult make_native_engine_config(
    const exv::Config &cfg, const std::string &plaintext_password,
    exv::vpn_engine::VpnEngineConfig *out) {
  if (!out) {
    return invalid("invalid_output",
                   "Native engine config output pointer is null.");
  }

  auto validation = validate_native_app_config(cfg);
  if (!validation.ok) {
    return validation;
  }
  NativeExtraArgs extra;
  auto extra_result = parse_native_extra_args(cfg.extra_args, &extra);
  if (!extra_result.ok)
    return extra_result;

  exv::vpn_engine::VpnEngineConfig engine_cfg;
  engine_cfg.engine = cfg.vpn_engine;
  engine_cfg.server = cfg.server;
  engine_cfg.username = cfg.username;
  engine_cfg.password = plaintext_password;
  engine_cfg.useragent = cfg.useragent;
  engine_cfg.mtu = cfg.mtu;
  engine_cfg.routes = cfg.routes;
  engine_cfg.windows_tunnel_driver = cfg.windows_tunnel_driver;
  engine_cfg.windows_tap_interface = cfg.windows_tap_interface;
  engine_cfg.auto_reconnect = cfg.auto_reconnect;
  engine_cfg.retry_limit =
      exv::config_detail::normalize_retry_limit(cfg.retry_limit);
  engine_cfg.disable_dtls = cfg.disable_dtls;
  engine_cfg.dtls_mode =
      cfg.disable_dtls
          ? "disabled"
          : (exv::config_detail::is_valid_dtls_mode(cfg.dtls_mode)
                 ? cfg.dtls_mode
                 : "auto");
  if (engine_cfg.dtls_mode == "disabled")
    engine_cfg.disable_dtls = true;
  if (extra.no_dtls) {
    engine_cfg.disable_dtls = true;
    engine_cfg.dtls_mode = "disabled";
  }
  if (!extra.useragent.empty())
    engine_cfg.useragent = std::move(extra.useragent);
  engine_cfg.auth_group = std::move(extra.auth_group);
  engine_cfg.csd_wrapper = std::move(extra.csd_wrapper);

  *out = std::move(engine_cfg);
  return exv::vpn_engine::ValidationResult{};
}

} // namespace exv::core
