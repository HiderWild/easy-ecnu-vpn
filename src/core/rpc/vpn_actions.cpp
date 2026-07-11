#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "core/rpc/vpn_actions.hpp"
#include <nlohmann/json.hpp>
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/config/config_manager.hpp"
#include "runtime/runtime_context.hpp"

using json = nlohmann::json;

namespace exv::core_api {

VpnActions::VpnActions(std::shared_ptr<exv::core::TunnelController> controller)
    : controller_(std::move(controller)) {}

VpnActions::VpnActions(std::shared_ptr<exv::core::TunnelController> controller,
                       ConnectJobRunner connect_job_runner)
    : controller_(std::move(controller)),
      connect_job_runner_(std::move(connect_job_runner)) {}

void VpnActions::register_handlers(AppRpcDispatcher& dispatcher) {
    dispatcher.register_handler("vpn.connect",
        [this](const RpcRequest& req) { return connect(req); });
    dispatcher.register_handler("vpn.disconnect",
        [this](const RpcRequest& req) { return disconnect(req); });
    dispatcher.register_handler("vpn.status",
        [this](const RpcRequest& req) { return status(req); });
    dispatcher.register_handler("vpn.set_auto_reconnect",
        [this](const RpcRequest& req) { return set_auto_reconnect(req); });
    dispatcher.register_handler("status.get",
        [this](const RpcRequest& req) { return get_legacy_status(req); });
}

RpcResponse VpnActions::connect(const RpcRequest& req) {
    RpcResponse resp;
    try {
        auto payload = json::parse(req.payload_json);

        exv::core::UserIntent intent;
        intent.desired_connected = true;

        if (payload.contains("profile_id")) {
            intent.profile_id.value = payload["profile_id"].get<std::string>();
        }
        if (payload.contains("auto_reconnect")) {
            intent.auto_reconnect = payload["auto_reconnect"].get<bool>();
        }

        exv::core::PendingConnectRequest pending;
        pending.profile_id = intent.profile_id.value;
        pending.server = intent.profile_id.value;
        pending.has_password = payload.contains("password") &&
                               payload["password"].is_string() &&
                               !payload["password"].get<std::string>().empty();

        auto state = connect_jobs_.submit_connect(
            pending,
            [this, intent](std::stop_token stop, std::uint64_t epoch) mutable {
                if (connect_job_runner_) {
                    connect_job_runner_(stop, epoch);
                    return;
                }
                if (stop.stop_requested()) {
                    return;
                }
                controller_->connect(intent);
            });
        resp.success = true;
        resp.payload_json = connect_state_json(state).dump();
    } catch (const std::exception& e) {
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = e.what();
    }
    return resp;
}

RpcResponse VpnActions::disconnect(const RpcRequest& req) {
    RpcResponse resp;
    auto active = connect_jobs_.snapshot();
    if (active.active) {
        auto state =
            connect_jobs_.submit_disconnect("user_cancelled_connect");
        resp.success = true;
        resp.payload_json = connect_state_json(state).dump();
        return resp;
    }
    controller_->disconnect();
    resp.success = true;
    resp.payload_json = json{{"status", "disconnecting"}}.dump();
    return resp;
}

RpcResponse VpnActions::status(const RpcRequest& req) {
    RpcResponse resp;
    auto s = controller_->status();

    json result = {
        {"phase", exv::core::tunnel_phase_wire_name(s.phase)},
        {"desired_connected", s.desired_connected},
        {"auto_reconnect", s.auto_reconnect},
        {"helper_mode", s.helper_mode},
        {"helper_status", s.helper_status},
        {"helper_endpoint", s.helper_endpoint},
        {"core_lease_active", s.core_lease_active},
        {"session_active", s.session_active},
        {"network_ready", s.network_ready},
        {"server", s.server},
        {"interface_name", s.interface_name},
        {"internal_ip", s.internal_ip}
    };

    if (s.last_error.has_value()) {
        auto& err = s.last_error.value();
        result["last_error"] = {
            {"domain", err.domain},
            {"code", err.code},
            {"message", err.message},
            {"recoverable", err.recoverable},
            {"recommended_action", err.recommended_action}
        };
        if (err.native_code.has_value()) {
            result["last_error"]["native_code"] = err.native_code.value();
        }
        if (!err.native_api.empty()) {
            result["last_error"]["native_api"] = err.native_api;
        }
    }

    if (s.reconnect.has_value()) {
        result["reconnect"] = {
            {"attempt", s.reconnect->attempt},
            {"next_retry_ms", s.reconnect->next_retry_ms}
        };
    }

    resp.success = true;
    resp.payload_json = result.dump();
    return resp;
}

RpcResponse VpnActions::set_auto_reconnect(const RpcRequest& req) {
    RpcResponse resp;
    try {
        auto payload = json::parse(req.payload_json);
        bool enabled = payload.at("enabled").get<bool>();
        controller_->set_auto_reconnect(enabled);
        resp.success = true;
        resp.payload_json = json{{"auto_reconnect", enabled}}.dump();
    } catch (const std::exception& e) {
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = e.what();
    }
    return resp;
}

RpcResponse VpnActions::get_legacy_status(const RpcRequest& req) {
    RpcResponse resp;
    try {
        exv::Config cfg;
        if (exv::runtime::is_bootstrapped()) {
            exv::config::ConfigManager mgr(exv::platform::get_config_dir());
            cfg = mgr.load();
        } else {
            cfg = exv::Config{};
        }

        auto snap = controller_ ? controller_->status() : exv::core::TunnelStatusSnapshot{};

        json result;
        result["phase"] = exv::core::tunnel_phase_wire_name(snap.phase);
        result["connected"] = snap.phase == exv::core::TunnelPhase::Connected;
        result["process_running"] = snap.phase != exv::core::TunnelPhase::Idle &&
                                    snap.phase != exv::core::TunnelPhase::Failed;
        result["auto_reconnect"] = snap.auto_reconnect;
        result["server"] = !snap.server.empty() ? snap.server : cfg.server;
        result["username"] = cfg.username;
        result["interface"] = snap.interface_name;
        result["internal_ip"] = snap.internal_ip;
        result["network_ready"] = snap.network_ready;

        if (snap.last_error.has_value()) {
            const auto& err = snap.last_error.value();
            result["last_error"] = {
                {"domain", err.domain},
                {"code", err.code},
                {"message", err.message},
                {"recoverable", err.recoverable},
                {"recommended_action", err.recommended_action}
            };
            if (err.native_code.has_value()) {
                result["last_error"]["native_code"] = err.native_code.value();
            }
            if (!err.native_api.empty()) {
                result["last_error"]["native_api"] = err.native_api;
            }
        }

        resp.success = true;
        resp.payload_json = result.dump();
    } catch (const std::exception& e) {
        resp.success = false;
        resp.error_code = "status_failed";
        resp.error_message = e.what();
    }
    return resp;
}

nlohmann::json VpnActions::connect_state_json(
    const exv::core::VpnConnectJobState& state) const {
    nlohmann::json out;
    out["accepted"] = state.accepted;
    out["phase"] = state.phase.empty() ? "connecting" : state.phase;
    out["job_id"] = state.job_id;
    out["active_job_id"] = state.job_id;
    out["active"] = state.active;
    out["coalesced"] = state.coalesced;
    out["cancelling"] = state.cancelling;
    out["user_cancelled"] = state.user_cancelled;
    out["desired_connected"] = state.desired_connected;
    out["intent_epoch"] = state.intent_epoch;
    if (!state.last_error_code.empty()) {
        out["last_error"] = {
            {"code", state.last_error_code},
            {"message", state.last_error_message}
        };
    }
    return out;
}

} // namespace exv::core_api
