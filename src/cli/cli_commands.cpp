#include "cli/cli_commands.hpp"

#include "cli/core_request_formatter.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <sstream>

namespace exv::cli {
namespace {

struct ParsedArgs {
  std::vector<std::string> positional;
  int retry_limit = 0;
  bool retry_specified = false;
  std::string error;
};

std::optional<int> try_parse_int(const std::string &value) {
  try {
    size_t parsed = 0;
    int result = std::stoi(value, &parsed);
    if (parsed != value.size()) {
      return std::nullopt;
    }
    return result;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<bool> try_parse_bool(const std::string &value) {
  if (value == "true" || value == "1" || value == "yes" || value == "on") {
    return true;
  }
  if (value == "false" || value == "0" || value == "no" || value == "off") {
    return false;
  }
  return std::nullopt;
}

bool is_one_of(const std::string &value,
               std::initializer_list<const char *> candidates) {
  return std::any_of(candidates.begin(), candidates.end(),
                     [&](const char *candidate) { return value == candidate; });
}

ParsedArgs parse_args(const std::vector<std::string> &args) {
  ParsedArgs parsed;
  for (size_t i = 1; i < args.size(); ++i) {
    const std::string &arg = args[i];
    if (arg == "-rt") {
      if (parsed.retry_specified) {
        parsed.error = "-rt can only be specified once.";
        return parsed;
      }
      parsed.retry_specified = true;
      parsed.retry_limit = 0;
      if (i + 1 < args.size()) {
        auto value = try_parse_int(args[i + 1]);
        if (value.has_value()) {
          if (*value < 0) {
            parsed.error = "-rt only accepts 0 or positive.";
            return parsed;
          }
          parsed.retry_limit = *value;
          ++i;
        }
      }
      continue;
    }
    parsed.positional.push_back(arg);
  }
  return parsed;
}

std::ostream &out_stream(const CliCommandDeps &deps) {
  return deps.out ? *deps.out : std::cout;
}

std::ostream &err_stream(const CliCommandDeps &deps) {
  return deps.err ? *deps.err : std::cerr;
}

std::string response_payload_text(const nlohmann::json &response) {
  if (!response.contains("payload_json")) {
    return "{}";
  }
  const auto &payload = response["payload_json"];
  return payload.is_string() ? payload.get<std::string>() : payload.dump();
}

void print_payload_response(const nlohmann::json &response, std::ostream &out) {
  const std::string payload_text = response_payload_text(response);
  try {
    out << nlohmann::json::parse(payload_text).dump(2) << '\n';
  } catch (...) {
    out << payload_text << '\n';
  }
}

bool should_print_payload(const std::string &action) {
  return is_one_of(action, {"status.get", "config.get", "routes.list",
                            "key.status", "logs.list", "service.status"});
}

std::string success_message_for_action(const std::string &action) {
  if (action == "vpn.connect") {
    return "VPN connect request submitted. Use `exv status` to follow progress.";
  }
  if (action == "vpn.disconnect") {
    return "VPN disconnect request submitted.";
  }
  if (action == "config.saveAuth" || action == "config.saveSettings") {
    return "Configuration saved.";
  }
  if (action == "config.reset") {
    return "Configuration reset.";
  }
  if (action == "routes.add" || action == "routes.remove" ||
      action == "routes.reset") {
    return "Routes updated.";
  }
  if (action == "key.reset") {
    return "Encryption key reset.";
  }
  if (action == "logs.clear") {
    return "Logs cleared.";
  }
  if (action == "service.install" || action == "service.uninstall") {
    return "Service operation submitted.";
  }
  return "OK";
}

bool response_ok(const std::string &line, const std::string &action,
                 std::ostream &out, std::ostream &err) {
  if (line.empty()) {
    err << "Core did not return a response.\n";
    return false;
  }
  try {
    auto response = nlohmann::json::parse(line);
    if (response.value("success", false)) {
      if (should_print_payload(action)) {
        print_payload_response(response, out);
      } else {
        out << success_message_for_action(action) << '\n';
      }
      return true;
    }
    err << response.value("error_message", response.value("error", "Core request failed.")) << '\n';
  } catch (const std::exception &e) {
    err << "Invalid core response: " << e.what() << '\n';
  }
  return false;
}

int send_action(const CliCommandDeps &deps,
                const CliCoreResolution &core,
                const std::string &action,
                const nlohmann::json &payload = nlohmann::json::object()) {
  if (!deps.send_core_request) {
    err_stream(deps) << "Core IPC client is unavailable.\n";
    return 1;
  }
  const std::string response =
      deps.send_core_request(core.ipc_path, format_core_request(action, payload));
  return response_ok(response, action, out_stream(deps), err_stream(deps)) ? 0 : 1;
}

std::optional<CliCoreResolution> resolve_or_fail(const CliCommandDeps &deps) {
  if (!deps.resolve_core) {
    err_stream(deps) << "Core resolver is unavailable.\n";
    return std::nullopt;
  }
  CliCoreResolution core = deps.resolve_core();
  if (!core.ok) {
    err_stream(deps) << (core.message.empty() ? "Unable to resolve core." : core.message) << '\n';
    return std::nullopt;
  }
  return core;
}

int handle_start(const CliCommandDeps &deps, const ParsedArgs &parsed) {
  auto core = resolve_or_fail(deps);
  if (!core.has_value()) {
    return 1;
  }
  if (parsed.retry_specified) {
    nlohmann::json payload;
    payload["settings"] = nlohmann::json{{"auto_reconnect", true},
                                          {"retry_limit", parsed.retry_limit}};
    int rc = send_action(deps, *core, "config.saveSettings", payload);
    if (rc != 0) {
      return rc;
    }
  }
  return send_action(deps, *core, "vpn.connect");
}

int handle_routes(const std::vector<std::string> &args,
                  const CliCommandDeps &deps,
                  std::size_t subcommand_index) {
  const std::string subcmd =
      args.size() > subcommand_index ? args[subcommand_index] : "list";

  if (subcmd == "list" || subcmd == "show") {
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "routes.list") : 1;
  }

  if (subcmd == "add") {
    if (args.size() <= subcommand_index + 1) {
      err_stream(deps) << "Usage: exv config routes add <cidr>\n";
      return 1;
    }
    auto core = resolve_or_fail(deps);
    return core.has_value()
               ? send_action(deps, *core, "routes.add",
                             nlohmann::json{{"cidr", args[subcommand_index + 1]}})
               : 1;
  }

  if (subcmd == "remove" || subcmd == "delete" || subcmd == "rm") {
    if (args.size() <= subcommand_index + 1) {
      err_stream(deps) << "Usage: exv config routes remove <cidr>\n";
      return 1;
    }
    auto core = resolve_or_fail(deps);
    return core.has_value()
               ? send_action(deps, *core, "routes.remove",
                             nlohmann::json{{"cidr", args[subcommand_index + 1]}})
               : 1;
  }

  if (subcmd == "reset") {
    const bool explicit_confirm = std::find(args.begin() + subcommand_index + 1,
                                            args.end(), "--confirm") != args.end();
    if (!explicit_confirm) {
      if (!deps.interactive) {
        err_stream(deps) << "routes reset requires --confirm in non-interactive mode.\n";
        return 1;
      }
      if (!deps.confirm || !deps.confirm("Reset routes?")) {
        err_stream(deps) << "Route reset cancelled.\n";
        return 1;
      }
    }
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "routes.reset") : 1;
  }

  err_stream(deps) << "Unknown routes subcommand: " << subcmd << '\n';
  return 1;
}

int handle_key(const std::vector<std::string> &args,
               const CliCommandDeps &deps,
               std::size_t subcommand_index) {
  const std::string subcmd =
      args.size() > subcommand_index ? args[subcommand_index] : "status";

  if (subcmd == "status" || subcmd == "show") {
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "key.status") : 1;
  }

  if (subcmd == "reset") {
    const bool explicit_confirm = std::find(args.begin() + subcommand_index + 1,
                                            args.end(), "--confirm") != args.end();
    if (!explicit_confirm) {
      if (!deps.interactive) {
        err_stream(deps) << "key reset requires --confirm in non-interactive mode.\n";
        return 1;
      }
      if (!deps.confirm || !deps.confirm("Reset encryption key?")) {
        err_stream(deps) << "Key reset cancelled.\n";
        return 1;
      }
    }
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "key.reset") : 1;
  }

  err_stream(deps) << "Unknown key subcommand: " << subcmd << '\n';
  return 1;
}

int handle_logs(const std::vector<std::string> &args,
                const CliCommandDeps &deps) {
  const std::string subcmd = args.size() > 2 ? args[2] : "list";

  if (subcmd == "list" || subcmd == "show") {
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "logs.list") : 1;
  }

  if (subcmd == "clear") {
    const bool explicit_confirm =
        std::find(args.begin() + 3, args.end(), "--confirm") != args.end();
    if (!explicit_confirm) {
      if (!deps.interactive) {
        err_stream(deps) << "logs clear requires --confirm in non-interactive mode.\n";
        return 1;
      }
      if (!deps.confirm || !deps.confirm("Clear logs?")) {
        err_stream(deps) << "Log clear cancelled.\n";
        return 1;
      }
    }
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "logs.clear") : 1;
  }

  err_stream(deps) << "Unknown logs subcommand: " << subcmd << '\n';
  return 1;
}

int handle_config(const std::vector<std::string> &args, const CliCommandDeps &deps) {
  const std::string subcmd = args.size() > 2 ? args[2] : "show";

  if (subcmd == "show") {
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "config.get") : 1;
  }

  if (subcmd == "set") {
    if (args.size() < 5) {
      err_stream(deps) << "Usage: exv config set <key> <value>\n";
      return 1;
    }
    const std::string &key = args[3];
    const std::string &value = args[4];
    std::string action;
    nlohmann::json payload;
    if (key == "server" || key == "username" || key == "user_agent" ||
        key == "useragent") {
      action = "config.saveAuth";
      payload[key == "useragent" ? "user_agent" : key] = value;
    } else if (key == "mtu" || key == "retry_limit") {
      auto parsed_value = try_parse_int(value);
      if (!parsed_value.has_value()) {
        err_stream(deps) << "Config key '" << key << "' requires an integer value.\n";
        return 1;
      }
      if (key == "retry_limit" && *parsed_value < 0) {
        err_stream(deps)
            << "Config key 'retry_limit' requires 0 or positive.\n";
        return 1;
      }
      action = "config.saveSettings";
      payload["settings"] = nlohmann::json{{key, *parsed_value}};
    } else if (key == "dtls_mode") {
      if (!is_one_of(value, {"auto", "enabled", "disabled"})) {
        err_stream(deps)
            << "Config key 'dtls_mode' requires auto, enabled, or disabled.\n";
        return 1;
      }
      action = "config.saveSettings";
      payload["settings"] = nlohmann::json{{key, value}};
    } else if (is_one_of(key, {"dtls", "disable_dtls", "remember_password",
                               "auto_reconnect", "minimal_mode",
                               "service_install_prompt_seen",
                               "minimal_install_service_before_connect",
                               "include_class_a_private_routes",
                               "include_class_b_private_routes",
                               "launch_at_login",
                               "auto_connect_on_launch",
                               "silent_startup",
                               "connection_state_notifications"})) {
      auto parsed_value = try_parse_bool(value);
      if (!parsed_value.has_value()) {
        err_stream(deps) << "Config key '" << key << "' requires true or false.\n";
        return 1;
      }
      if (key == "remember_password") {
        action = "config.saveAuth";
        payload[key] = *parsed_value;
      } else {
        action = "config.saveSettings";
        payload["settings"] = nlohmann::json{{key, *parsed_value}};
      }
    } else if (is_one_of(key, {"log_path", "log_file", "vpn_engine",
                               "windows_tunnel_driver",
                               "windows_tap_interface"})) {
      action = "config.saveSettings";
      payload["settings"] = nlohmann::json{{key, value}};
    } else {
      err_stream(deps) << "Unknown config key: " << key << '\n';
      return 1;
    }

    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, action, payload) : 1;
  }

  if (subcmd == "reset") {
    const bool explicit_confirm =
        std::find(args.begin() + 3, args.end(), "--confirm") != args.end();
    if (!explicit_confirm) {
      if (!deps.interactive) {
        err_stream(deps) << "config reset requires --confirm in non-interactive mode.\n";
        return 1;
      }
      if (!deps.confirm || !deps.confirm("Reset configuration?")) {
        err_stream(deps) << "Configuration reset cancelled.\n";
        return 1;
      }
    }
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "config.reset") : 1;
  }

  if (subcmd == "routes" || subcmd == "route") {
    return handle_routes(args, deps, 3);
  }

  if (subcmd == "key") {
    return handle_key(args, deps, 3);
  }

  err_stream(deps) << "Unknown config subcommand: " << subcmd << '\n';
  return 1;
}

void print_help(std::ostream &out, const std::string &program) {
  out << "Usage: " << program << " [command] [options]\n"
      << "Commands: start, stop, status, config, routes, logs, service, version, help\n";
}

} // namespace

int run_cli_command(const std::vector<std::string> &raw_args, CliCommandDeps deps) {
  ParsedArgs parsed = parse_args(raw_args);
  if (!parsed.error.empty()) {
    err_stream(deps) << parsed.error << '\n';
    return 1;
  }

  std::vector<std::string> args;
  args.emplace_back(raw_args.empty() ? "exv-cli" : raw_args[0]);
  args.insert(args.end(), parsed.positional.begin(), parsed.positional.end());
  if (args.size() <= 1) {
    args.push_back("start");
  }

  const std::string cmd = args[1];
  if (parsed.retry_specified && cmd != "start") {
    err_stream(deps) << "-rt can only be used with start.\n";
    return 1;
  }

  if (cmd == "help" || cmd == "-h" || cmd == "--help") {
    print_help(out_stream(deps), args[0]);
    return 0;
  }
  if (cmd == "version" || cmd == "-v" || cmd == "--version") {
    if (!deps.version_probe) {
      err_stream(deps) << "Core version probe is unavailable.\n";
      return 1;
    }
    out_stream(deps) << deps.version_probe();
    return 0;
  }
  if (cmd == "start") {
    return handle_start(deps, parsed);
  }
  if (cmd == "stop" || cmd == "-s") {
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "vpn.disconnect") : 1;
  }
  if (cmd == "status" || cmd == "-t") {
    auto core = resolve_or_fail(deps);
    return core.has_value() ? send_action(deps, *core, "status.get") : 1;
  }
  if (cmd == "config" || cmd == "-c") {
    return handle_config(args, deps);
  }
  if (cmd == "routes" || cmd == "route") {
    return handle_routes(args, deps, 2);
  }
  if (cmd == "logs" || cmd == "log") {
    return handle_logs(args, deps);
  }
  if (cmd == "service") {
    const std::string subcmd = args.size() > 2 ? args[2] : "status";
    if (subcmd == "install") {
      auto core = resolve_or_fail(deps);
      return core.has_value() ? send_action(deps, *core, "service.install") : 1;
    }
    if (subcmd == "uninstall") {
      auto core = resolve_or_fail(deps);
      return core.has_value() ? send_action(deps, *core, "service.uninstall") : 1;
    }
    if (subcmd == "status") {
      auto core = resolve_or_fail(deps);
      return core.has_value() ? send_action(deps, *core, "service.status") : 1;
    }
    err_stream(deps) << "Unknown service subcommand: " << subcmd << '\n';
    return 1;
  }

  err_stream(deps) << "Unknown command: " << cmd << '\n';
  return 1;
}

} // namespace exv::cli
