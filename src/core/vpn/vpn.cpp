#include "core/vpn/vpn.hpp"
#include "core/app_api/app_api.hpp"
#include "core/config/config.hpp"
#include "core/tunnel_controller/native_engine_config_mapper.hpp"
#include "helper/helper.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "common/diagnostics/log_renderer.hpp"
#include "runtime/runtime_context.hpp"
#include "cli/console.hpp"

#include <iostream>

namespace exv {
namespace vpn {

int start(const Config &cfg, int retry_limit) {
  // Enable log rendering for CLI mode - subscribes to LogEventBus
  exv::LogRenderer log_renderer;

  exv::observability::LogFacade::info("VPN CLI: Connection starting - server=" + cfg.server +
               " username=" + cfg.username + " engine=" + cfg.vpn_engine);

  cli::print_header("EXV Starting");

  if (cfg.vpn_engine != "native") {
    cli::print_error("VPN engine is native-only.");
    exv::observability::LogFacade::error(
        "VPN CLI: rejected non-native engine");
    return 1;
  }
  if (retry_limit < 0) {
    cli::print_error("retry_limit must be 0 or a positive integer.");
    return 1;
  }

  exv::observability::LogFacade::info("VPN CLI: Validating native engine configuration");
  auto validation = exv::core::validate_native_app_config(cfg);
  if (!validation.ok) {
    cli::print_error(validation.message);
    exv::observability::LogFacade::error("VPN CLI: Native engine validation failed - code=" +
                  validation.code + " message=" + validation.message);
    return 1;
  }
  exv::observability::LogFacade::info("VPN CLI: Native engine configuration validated successfully");

  nlohmann::json payload;
  payload["password"] = config::get_plaintext_password(cfg);
  payload["retry_limit"] = retry_limit;

  exv::observability::LogFacade::info("VPN CLI: Calling app_api::handle_action(vpn.connect)");
  nlohmann::json result = app_api::handle_action("vpn.connect", payload);

  if (result.is_object() && result.value("ok", true) == false) {
    std::string msg = result.value("error", std::string("Connection failed"));
    std::string code = result.value("code", std::string());
    cli::print_error(msg);
    exv::observability::LogFacade::error("VPN CLI: Connection failed - code=" + code + " error=" + msg);
    return 1;
  }

  exv::observability::LogFacade::info("VPN CLI: Connection initiated successfully");
  cli::print_success("VPN connection initiated");
  return 0;
}

int stop() {
  nlohmann::json result = app_api::handle_action("vpn.disconnect", nlohmann::json::object());
  if (result.is_object() && result.value("ok", true) == false) {
    cli::print_error(result.value("error", std::string("Disconnect failed")));
    return 1;
  }
  cli::print_success("VPN disconnected");
  return 0;
}

int status() {
  nlohmann::json result = app_api::handle_action("status.get", nlohmann::json::object());

  if (result.is_object() && result.value("ok", true) == false) {
    cli::print_error("Failed to get VPN status");
    return 1;
  }

  bool connected = result.value("connected", false);
  if (connected) {
    std::cout << cli::GREEN << cli::BOLD << "  ● VPN is RUNNING" << cli::RESET << std::endl;
    std::cout << std::endl;
    std::cout << "  Server         : " << result.value("server", std::string()) << std::endl;
    std::cout << "  Interface      : " << result.value("interface", std::string()) << std::endl;
    std::cout << "  Network Ready  : " << (result.value("network_ready", false) ? "yes" : "no") << std::endl;
  } else {
    std::cout << cli::RED << cli::BOLD << "  ● VPN is NOT RUNNING" << cli::RESET << std::endl;
  }
  std::cout << std::endl;
  return 0;
}

} // namespace vpn
} // namespace exv
