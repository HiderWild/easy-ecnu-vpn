#include "core/tunnel_controller/tunnel_controller_impl.hpp"

namespace exv::core {

// ================================================================
// State transition helpers
// ================================================================

void TunnelController::Impl::transition_to(TunnelPhase new_phase) {
        if (new_phase == TunnelPhase::Idle ||
            new_phase == TunnelPhase::Failed ||
            new_phase == TunnelPhase::CleaningUp) {
            stop_heartbeat();
        }
        phase_ = new_phase;
        update_snapshot();
        notify_status();
    }

void TunnelController::Impl::update_snapshot() {
        snapshot_.runtime_epoch   = runtime_epoch_;
        snapshot_.controller_id   = controller_id_;
        snapshot_.phase            = phase_;
        snapshot_.desired_connected = intent_.desired_connected;
        snapshot_.auto_reconnect   = intent_.auto_reconnect;
        snapshot_.server           = intent_.profile_id.value;
        auto engine_status = runner_.status();
        snapshot_.interface_name =
            engine_status.interface_name.empty()
                ? adapter_name_
                : engine_status.interface_name;
        snapshot_.internal_ip =
            engine_status.internal_ip.empty()
                ? assigned_internal_ip_
                : engine_status.internal_ip;
        snapshot_.dtls_mode = engine_status.dtls_mode;
        snapshot_.active_data_channel = engine_status.active_data_channel;
        snapshot_.dtls_state = engine_status.dtls_state;
        snapshot_.dtls_fallback_reason = engine_status.dtls_fallback_reason;
        snapshot_.dtls_fallback_count = engine_status.dtls_fallback_count;

        if (!helper_status_override_.empty()) {
            snapshot_.helper_status = helper_status_override_;
        } else if (helper_ && (helper_->is_connected() || helper_connected_seen_)) {
            snapshot_.helper_status = "connected";
        } else {
            snapshot_.helper_status = "unavailable";
        }
        snapshot_.helper_mode = helper_mode_;
        snapshot_.helper_endpoint = helper_endpoint_;
        snapshot_.core_lease_active = !core_lease_id_.empty();
        snapshot_.session_active = !session_id_.value.empty();

        // Network-ready is true once we have fully connected.
        snapshot_.network_ready = (phase_ == TunnelPhase::Connected);

        // Reconnect bookkeeping
        if (phase_ == TunnelPhase::Reconnecting) {
            ReconnectInfo ri;
            ri.attempt       = reconnect_attempts_;
            ri.next_retry_ms = static_cast<int>(reconnect_policy_.next_delay().count());
            snapshot_.reconnect = ri;
        } else {
            snapshot_.reconnect = std::nullopt;
        }
    }

void TunnelController::Impl::notify_status() {
        if (status_callback_) {
            status_callback_(snapshot_);
        }
    }

void TunnelController::Impl::set_error(const ErrorInfo& error) {
        snapshot_.last_error = error;
    }

void TunnelController::Impl::clear_error() {
        snapshot_.last_error = std::nullopt;
    }

bool TunnelController::Impl::helper_control_plane_loss_is_degradable() const {
        return phase_ == TunnelPhase::Connected ||
               runner_.is_running() ||
               !session_id_.value.empty() ||
               network_config_applied_ ||
               packet_loop_started_;
    }

bool TunnelController::Impl::clear_helper_control_plane_error() {
        if (!snapshot_.last_error || snapshot_.last_error->domain != "helper") {
            return false;
        }

        const std::string& code = snapshot_.last_error->code;
        if (code != "helper_lost" &&
            code != "helper_pipe_disconnected") {
            return false;
        }

        clear_error();
        return true;
    }

void TunnelController::Impl::mark_helper_control_plane_degraded(
        const std::string& reason,
        const std::string& detail) {
        stop_heartbeat();
        stop_core_lease_keepalive();
        core_lease_id_.clear();
        helper_connected_seen_ = false;
        helper_status_override_ = "unavailable";
        const bool cleared_error = clear_helper_control_plane_error();
        update_snapshot();
        log_tunnel_event(
            "WARN", "helper.control_plane.degraded",
            "Helper control plane is unavailable while VPN data plane may continue",
            {{"reason", reason},
             {"detail", detail},
             {"phase", tunnel_phase_wire_name(phase_)},
             {"runner_running", runner_.is_running() ? "true" : "false"},
             {"session_active", snapshot_.session_active ? "true" : "false"},
             {"network_config_applied",
              network_config_applied_ ? "true" : "false"},
             {"packet_loop_started", packet_loop_started_ ? "true" : "false"},
             {"network_ready", snapshot_.network_ready ? "true" : "false"},
             {"cleared_error", cleared_error ? "true" : "false"}});
        notify_status();
    }

} // namespace exv::core
