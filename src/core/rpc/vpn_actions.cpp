#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "core/rpc/vpn_actions.hpp"
#include <nlohmann/json.hpp>
#include "core/tunnel_controller/connect_progress_json.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/config/config_manager.hpp"
#include "core/use_cases/tunnel_use_cases.hpp"
#include "runtime/runtime_context.hpp"

using json = nlohmann::json;

namespace exv::core_api {

namespace {

bool connect_progress_is_inactive(
    const exv::core::ConnectProgress& progress) {
    if (!progress.active_key.empty()) {
        return false;
    }
    for (const auto& step : progress.steps) {
        if (step.state != exv::core::ConnectProgressStepState::Pending) {
            return false;
        }
    }
    return true;
}

bool active_connect_job(const exv::core::VpnConnectJobState& job) {
    return job.active && job.desired_connected;
}

} // namespace

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

        if (!connect_job_runner_ &&
            (exv::core::tunnel_use_cases().current_runtime_is_connected() ||
             exv::core::tunnel_use_cases()
                 .current_runtime_is_connecting_or_recovering())) {
            return status(req);
        }

        auto state = connect_jobs().submit_connect(
            pending,
            [this, intent](std::stop_token stop, std::uint64_t epoch) mutable {
                if (connect_job_runner_) {
                    connect_job_runner_(stop, epoch);
                    return;
                }
                if (stop.stop_requested()) {
                    return;
                }
                if (auto controller = controller_for_mutation(); controller) {
                    controller->connect(intent);
                }
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
    auto active = connect_jobs().snapshot();
    if (active.active) {
        auto state =
            connect_jobs().submit_disconnect("user_cancelled_connect");
        resp.success = true;
        resp.payload_json = connect_state_json(state).dump();
        return resp;
    }
    if (auto controller = controller_for_mutation(); controller) {
        controller->disconnect();
    }
    resp.success = true;
    resp.payload_json = json{{"status", active.active ? "disconnecting" : "idle"}}.dump();
    return resp;
}

RpcResponse VpnActions::status(const RpcRequest& req) {
    RpcResponse resp;
    auto controller = controller_for_status();
    auto s = controller ? controller->status() : exv::core::TunnelStatusSnapshot{};
    const auto job = current_connect_job();
    const bool use_job_overlay =
        active_connect_job(job) && connect_progress_is_inactive(s.connect_progress);
    const auto& progress =
        use_job_overlay ? job.connect_progress : s.connect_progress;
    const std::string phase =
        use_job_overlay
            ? (job.phase.empty() ? std::string("connecting") : job.phase)
            : std::string(exv::core::tunnel_phase_wire_name(s.phase));

    json result = {
        {"phase", phase},
        {"desired_connected", use_job_overlay ? true : s.desired_connected},
        {"auto_reconnect", s.auto_reconnect},
        {"helper_mode", s.helper_mode},
        {"helper_status", s.helper_status},
        {"helper_endpoint", s.helper_endpoint},
        {"core_lease_active", s.core_lease_active},
        {"session_active", s.session_active},
        {"network_ready", s.network_ready},
        {"server", s.server},
        {"interface_name", s.interface_name},
        {"internal_ip", s.internal_ip},
        {"dtls_mode", s.dtls_mode},
        {"active_data_channel", s.active_data_channel},
        {"dtls_state", s.dtls_state},
        {"dtls_fallback_reason", s.dtls_fallback_reason},
        {"dtls_fallback_count", s.dtls_fallback_count},
        {"connect_progress", exv::core::connect_progress_to_json(progress)}
    };
    if (use_job_overlay) {
        result["connect_job_id"] = job.job_id;
        result["connect_intent_epoch"] = job.intent_epoch;
    }

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
        auto controller = controller_for_mutation();
        if (!controller) {
            resp.success = false;
            resp.error_code = "invalid_state";
            resp.error_message = "No live VPN controller is available.";
            return resp;
        }
        controller->set_auto_reconnect(enabled);
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

        auto controller = controller_for_status();
        auto snap = controller ? controller->status() : exv::core::TunnelStatusSnapshot{};
        const auto job = current_connect_job();
        const bool use_job_overlay =
            active_connect_job(job) &&
            connect_progress_is_inactive(snap.connect_progress);
        const std::string phase =
            use_job_overlay
                ? (job.phase.empty() ? std::string("connecting") : job.phase)
                : std::string(exv::core::tunnel_phase_wire_name(snap.phase));

        json result;
        result["phase"] = phase;
        result["connected"] =
            !use_job_overlay && snap.phase == exv::core::TunnelPhase::Connected;
        result["process_running"] =
            use_job_overlay ||
            (snap.phase != exv::core::TunnelPhase::Idle &&
             snap.phase != exv::core::TunnelPhase::Failed);
        result["auto_reconnect"] = snap.auto_reconnect;
        result["server"] = !snap.server.empty() ? snap.server : cfg.server;
        result["username"] = cfg.username;
        result["interface"] = snap.interface_name;
        result["internal_ip"] = snap.internal_ip;
        result["dtls_mode"] = snap.dtls_mode;
        result["active_data_channel"] = snap.active_data_channel;
        result["dtls_state"] = snap.dtls_state;
        result["dtls_fallback_reason"] = snap.dtls_fallback_reason;
        result["dtls_fallback_count"] = snap.dtls_fallback_count;
        result["network_ready"] = use_job_overlay ? false : snap.network_ready;
        result["connect_progress"] = exv::core::connect_progress_to_json(
            use_job_overlay ? job.connect_progress : snap.connect_progress);
        if (use_job_overlay) {
            result["connect_job_id"] = job.job_id;
            result["connect_intent_epoch"] = job.intent_epoch;
            result["connect_cancelling"] = job.cancelling;
        }

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

exv::core::VpnConnectJobOwner& VpnActions::connect_jobs() {
    if (connect_job_runner_) {
        return connect_jobs_;
    }
    return exv::core::tunnel_use_cases().connect_jobs();
}

exv::core::VpnConnectJobState VpnActions::current_connect_job() const {
    if (connect_job_runner_) {
        return connect_jobs_.snapshot();
    }
    return exv::core::tunnel_use_cases().connect_jobs().snapshot();
}

std::shared_ptr<exv::core::TunnelController>
VpnActions::controller_for_status() const {
    if (auto live_controller =
            exv::core::tunnel_use_cases().controller_if_exists();
        live_controller) {
        return live_controller;
    }
    return controller_;
}

std::shared_ptr<exv::core::TunnelController>
VpnActions::controller_for_mutation() const {
    if (auto live_controller =
            exv::core::tunnel_use_cases().controller_if_exists();
        live_controller) {
        return live_controller;
    }
    return controller_;
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
    out["connect_progress"] =
        exv::core::connect_progress_to_json(state.connect_progress);
    if (!state.last_error_code.empty()) {
        out["last_error"] = {
            {"code", state.last_error_code},
            {"message", state.last_error_message}
        };
    }
    return out;
}

} // namespace exv::core_api
