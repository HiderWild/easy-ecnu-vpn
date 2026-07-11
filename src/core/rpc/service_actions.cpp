#include "service_actions.hpp"

#include "core/tunnel_controller/tunnel_controller.hpp"
#include "platform/common/backend_resolver.hpp"
#include "platform/common/process_control.hpp"

#include <nlohmann/json.hpp>

#include <exception>
#include <memory>
#include <utility>

using json = nlohmann::json;

namespace exv::core_api {
namespace {

RpcResponse to_rpc_response(const exv::core::UseCaseResult &result) {
    RpcResponse resp;
    resp.success = result.success;
    if (result.success) {
        resp.payload_json = result.payload.dump();
    } else {
        resp.error_code = result.error_code;
        resp.error_message = result.error_message;
    }
    return resp;
}

RpcResponse invalid_payload_response(const std::exception &e) {
    return to_rpc_response(
        exv::core::UseCaseResult::fail("invalid_payload", e.what()));
}

bool active_vpn_session(const std::shared_ptr<exv::core::TunnelController> &controller) {
    if (!controller) {
        return false;
    }
    auto snap = controller->status();
    return snap.session_active || snap.network_ready || snap.desired_connected;
}

} // namespace

ServiceActions::ServiceActions() = default;

ServiceActions::ServiceActions(
    std::shared_ptr<exv::core::TunnelController> controller)
    : controller_(std::move(controller)) {}

ServiceActions::ServiceActions(std::string config_dir)
    : use_cases_(std::move(config_dir)) {}

ServiceActions::ServiceActions(
    std::string config_dir,
    std::shared_ptr<exv::core::TunnelController> controller)
    : use_cases_(std::move(config_dir)), controller_(std::move(controller)) {}

void ServiceActions::register_handlers(AppRpcDispatcher& dispatcher) {
    dispatcher.register_handler("service.helper_status",
        [this](const RpcRequest& req) { return helper_status(req); });
    dispatcher.register_handler("service.install",
        [this](const RpcRequest& req) { return install_helper(req); });
    dispatcher.register_handler("service.uninstall",
        [this](const RpcRequest& req) { return uninstall_helper(req); });
    dispatcher.register_handler("service.repair",
        [this](const RpcRequest& req) { return repair_helper(req); });
    dispatcher.register_handler("service.driver_status",
        [this](const RpcRequest& req) { return driver_status(req); });

    // Desktop API names (match webui/desktop/shared/desktop-contract.ts)
    dispatcher.register_handler("service.status",
        [this](const RpcRequest& req) { return helper_status(req); });
    dispatcher.register_handler("helper.status",
        [this](const RpcRequest& req) { return helper_status(req); });
    dispatcher.register_handler("drivers.status",
        [this](const RpcRequest& req) { return driver_status(req); });
    dispatcher.register_handler("drivers.install",
        [this](const RpcRequest& req) { return install_driver(req); });
}

RpcResponse ServiceActions::helper_status(const RpcRequest& req) {
    if (req.action == "service.status") {
        return to_rpc_response(use_cases_.service_status());
    }
    return to_rpc_response(use_cases_.helper_status());
}

RpcResponse ServiceActions::install_helper(const RpcRequest& req) {
    (void)req;
    // Installing the service while a one-shot helper has an active VPN session
    // is no longer handled by an in-daemon self-handoff (removed in A4). If a
    // session is active, disconnect it first and wait for the controller to
    // settle, then delegate to the shared install path, which launches the
    // elevated exv-helper.exe --install-service process (core-initiated runas).
    if (active_vpn_session(controller_)) {
        controller_->disconnect();
        constexpr int kDisconnectAttempts = 100;  // ~10s at 100ms
        for (int i = 0; i < kDisconnectAttempts; ++i) {
            auto snap = controller_->status();
            if (!snap.session_active && !snap.network_ready) {
                break;
            }
            exv::platform::sleep_ms(100);
        }
        auto snap = controller_->status();
        if (snap.session_active || snap.network_ready) {
            return to_rpc_response(exv::core::UseCaseResult::fail(
                "vpn_disconnect_timeout",
                "断开当前 VPN 会话超时，请稍后重试安装。"));
        }
    }
    return to_rpc_response(use_cases_.install_helper());
}

RpcResponse ServiceActions::uninstall_helper(const RpcRequest& req) {
    (void)req;
    if (active_vpn_session(controller_)) {
        return to_rpc_response(exv::core::UseCaseResult::fail(
            "vpn_session_active",
            "Disconnect the VPN session before uninstalling the helper service."));
    }
    return to_rpc_response(use_cases_.uninstall_helper());
}

RpcResponse ServiceActions::repair_helper(const RpcRequest& req) {
    (void)req;
    return to_rpc_response(use_cases_.repair_helper());
}

RpcResponse ServiceActions::driver_status(const RpcRequest& req) {
    return to_rpc_response(use_cases_.driver_status());
}

RpcResponse ServiceActions::install_driver(const RpcRequest& req) {
    try {
        auto payload = json::parse(req.payload_json);
        return to_rpc_response(use_cases_.install_driver(payload));
    } catch (const std::exception& e) {
        return invalid_payload_response(e);
    }
}

} // namespace exv::core_api
