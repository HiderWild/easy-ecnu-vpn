#include "core/app_api/desktop_system_actions.hpp"

#include "core/app_api/auth_interaction_coordinator.hpp"
#include "core/app_api/desktop_json.hpp"
#include "core/app_api/desktop_runtime_context.hpp"
#include "core/app_api/desktop_status_presenter.hpp"
#include "core/app_api/desktop_tunnel_host.hpp"
#include "core/connection/connection_attempt.hpp"
#include "core/rpc/desktop_rpc_adapter.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/use_cases/system_status_use_cases.hpp"
#include "core/use_cases/tunnel_use_cases.hpp"
#include "platform/common/process_control.hpp"
#include "platform/common/runtime_paths.hpp"

#include <exception>
#include <memory>
#include <mutex>
#include <string>
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

bool controller_cleanup_needed(
    const std::shared_ptr<exv::core::TunnelController> &controller) {
  if (!controller) {
    return false;
  }
  const auto snap = controller->status();
  if (snap.session_active || snap.network_ready || snap.desired_connected) {
    return true;
  }
  return snap.phase != exv::core::TunnelPhase::Idle &&
         snap.phase != exv::core::TunnelPhase::Failed;
}

bool connect_job_cleanup_needed() {
  auto &use_cases = exv::core::tunnel_use_cases();
  std::lock_guard<std::mutex> lock(use_cases.connect_jobs_mutex());
  const auto snap = use_cases.connect_jobs().snapshot();
  return snap.active || snap.cancelling || snap.desired_connected;
}

bool vpn_runtime_cleanup_needed() {
  return connect_job_cleanup_needed() ||
         static_cast<bool>(get_active_connect_auth_coordinator()) ||
         controller_cleanup_needed(get_tunnel_controller_if_exists());
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

exv::core::UseCaseResult
disconnect_vpn_runtime_for_service_operation(const char *reason) {
  std::string disconnect_reason = reason ? reason : "service_operation";
  if (disconnect_reason.empty()) {
    disconnect_reason = "service_operation";
  }

  exv::core::tunnel_use_cases().shutdown_connect_jobs(disconnect_reason);

  if (auto coordinator = get_active_connect_auth_coordinator(); coordinator) {
    coordinator->cancel();
    clear_active_connect_auth_coordinator_if_current(coordinator);
  }

  auto controller = get_tunnel_controller_if_exists();
  if (controller) {
    try {
      controller->disconnect(exv::core::DisconnectReason::UserRequested);
    } catch (const std::exception &e) {
      return exv::core::UseCaseResult::fail(
          "vpn_disconnect_failed",
          std::string("断开当前 VPN 会话失败：") + e.what());
    }

    constexpr int kDisconnectAttempts = 100; // ~10s at 100ms
    for (int i = 0; i < kDisconnectAttempts; ++i) {
      const auto snap = controller->status();
      if (!snap.session_active && !snap.network_ready &&
          !snap.desired_connected) {
        break;
      }
      exv::platform::sleep_ms(100);
    }

    const auto snap = controller->status();
    if (snap.session_active || snap.network_ready || snap.desired_connected) {
      return exv::core::UseCaseResult::fail(
          "vpn_disconnect_timeout",
          "断开当前 VPN 会话超时，请稍后重试服务操作。");
    }
  }

  exv::connection_attempt::mark_terminal(platform::get_config_dir(),
                                         disconnect_reason);
  exv::core::tunnel_use_cases().clear_connect_error();
  reset_tunnel_controller();
  return exv::core::UseCaseResult::ok();
}

exv::core::UseCaseResult install_helper_service_with_current_instance() {
  if (!vpn_runtime_cleanup_needed()) {
    return make_system_status_use_cases().install_helper();
  }
  auto disconnected =
      disconnect_vpn_runtime_for_service_operation("service_install");
  if (!disconnected.success) {
    return disconnected;
  }
  return make_system_status_use_cases().install_helper();
}

exv::core::UseCaseResult uninstall_helper_service_with_current_instance() {
  if (!vpn_runtime_cleanup_needed()) {
    return make_system_status_use_cases().uninstall_helper();
  }
  auto disconnected =
      disconnect_vpn_runtime_for_service_operation("service_uninstall");
  if (!disconnected.success) {
    return disconnected;
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
