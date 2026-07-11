#include "core/app_api/desktop_system_actions.hpp"

#include "core/app_api/desktop_json.hpp"
#include "core/app_api/desktop_runtime_context.hpp"
#include "core/app_api/desktop_status_presenter.hpp"
#include "core/app_api/desktop_tunnel_host.hpp"
#include "core/rpc/desktop_rpc_adapter.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/use_cases/system_status_use_cases.hpp"

#include <utility>

namespace exv {
namespace app_api {
namespace {

exv::core::SystemStatusUseCases make_system_status_use_cases() {
  return exv::core::SystemStatusUseCases();
}

nlohmann::json desktop_result(const exv::core::UseCaseResult &result) {
  if (!result.success) {
    nlohmann::json failure = error(result.error_message, result.error_code);
    if (result.payload.is_object() && !result.payload.empty()) {
      for (auto it = result.payload.begin(); it != result.payload.end(); ++it) {
        failure[it.key()] = it.value();
      }
    }
    return failure;
  }
  return result.payload;
}

bool current_vpn_session_active() {
  auto controller = get_tunnel_controller_if_exists();
  if (!controller) {
    return false;
  }
  const auto snap = controller->status();
  return snap.session_active || snap.network_ready || snap.desired_connected;
}

exv::core::UseCaseResult helper_status_with_current_instance() {
  auto use_cases = make_system_status_use_cases();
  auto helper = use_cases.helper_status();
  if (!helper.success) {
    return helper;
  }

  auto payload = helper.payload;
  auto service = use_cases.service_status();
  if (service.success) {
    payload["service_status"] = service.payload;
  }

  if (auto controller = get_tunnel_controller_if_exists()) {
    auto snap = controller->status();
    if (snap.helper_status != "unavailable") {
      payload["current_instance"] =
          helper_current_instance_from_controller_snapshot(snap);
    }
  }

  return exv::core::UseCaseResult::ok(std::move(payload));
}

exv::core::UseCaseResult install_helper_service_with_current_instance() {
  // NOTE: install-while-connected handling is rewritten in a follow-up task
  // (A5). The previous session-handoff chain has been removed; for now the
  // desktop install delegates to the shared helper maintenance path.
  return make_system_status_use_cases().install_helper();
}

exv::core::UseCaseResult uninstall_helper_service_with_current_instance() {
  if (current_vpn_session_active()) {
    return exv::core::UseCaseResult::fail(
        "vpn_session_active",
        "Disconnect the VPN session before uninstalling the helper service.");
  }
  // Uninstall is performed by a separate elevated exv-helper.exe
  // --uninstall-service process (see SystemStatusUseCases::uninstall_helper).
  // The running helper daemon is no longer asked to uninstall itself.
  return make_system_status_use_cases().uninstall_helper();
}

exv::core::UseCaseResult repair_helper_service() {
  return make_system_status_use_cases().repair_helper();
}

} // namespace

void register_desktop_system_actions(exv::core_api::DesktopRpcAdapter &adapter) {
  adapter.register_legacy_handler(
      "service.status", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(make_system_status_use_cases().service_status());
      });

  adapter.register_legacy_handler(
      "helper.status", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(helper_status_with_current_instance());
      });

  adapter.register_legacy_handler(
      "service.install", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(install_helper_service_with_current_instance());
      });

  adapter.register_legacy_handler(
      "service.uninstall", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(uninstall_helper_service_with_current_instance());
      });

  adapter.register_legacy_handler(
      "service.repair", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(repair_helper_service());
      });

  adapter.register_legacy_handler(
      "runtime.status", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(make_system_status_use_cases().runtime_status());
      });

  adapter.register_legacy_handler(
      "cli.status", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(make_system_status_use_cases().cli_status());
      });

  adapter.register_legacy_handler(
      "cli.install", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(make_system_status_use_cases().install_cli());
      });

  adapter.register_legacy_handler(
      "cli.uninstall", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(make_system_status_use_cases().uninstall_cli());
      });

  adapter.register_legacy_handler(
      "drivers.status", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(make_system_status_use_cases().driver_status());
      });

  adapter.register_legacy_handler(
      "drivers.install", [](const nlohmann::json &payload) -> nlohmann::json {
        apply_desktop_runtime_context(payload);
        return desktop_result(
            make_system_status_use_cases().install_driver(payload));
      });
}

} // namespace app_api
} // namespace exv
