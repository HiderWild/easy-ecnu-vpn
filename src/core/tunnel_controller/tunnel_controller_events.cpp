#include "core/tunnel_controller/tunnel_controller_impl.hpp"

#include <exception>

namespace exv::core {

// ================================================================
// Event handlers (called from on_event)
// ================================================================

void TunnelController::Impl::request_recovery(const std::string &reason,
                                              const ErrorInfo &error) {
        transition_to(TunnelPhase::Reconnecting);
        cleanup_after_recovery_request(reason);
        if (recovery_callback_) {
            recovery_callback_(TunnelRecoveryRequest{
                runtime_epoch_, controller_id_, reason, error});
        }
    }

void TunnelController::Impl::on_helper_ready() {
        if (phase_ == TunnelPhase::PreparingHelper) {
            timing_.timer.start(ConnectTiming::AUTH);
            transition_to(TunnelPhase::Authenticating);
        }
    }

void TunnelController::Impl::on_auth_succeeded() {
        if (phase_ == TunnelPhase::Authenticating) {
            timing_.timer.end(ConnectTiming::AUTH);
            timing_.timer.start(ConnectTiming::CSTP_CONNECT);
            transition_to(TunnelPhase::ConnectingCstp);
        }
    }

void TunnelController::Impl::on_auth_failed() {
        if (phase_ == TunnelPhase::Authenticating) {
            timing_.timer.end(ConnectTiming::AUTH);
            stop_heartbeat();
            set_error(CoreErrorMapper::from_auth_error(-1, "Authentication failed"));
            transition_to(TunnelPhase::Failed);
        }
    }

void TunnelController::Impl::on_cstp_connected() {
        if (phase_ == TunnelPhase::ConnectingCstp) {
            timing_.timer.end(ConnectTiming::CSTP_CONNECT);

            // When the native engine is active, apply the tunnel config
            // now and auto-advance the rest of the flow.
            if (runner_.is_running()) {
                apply_tunnel_config_and_advance();
            } else {
                timing_.timer.start(ConnectTiming::NETWORK_CONFIG);
                transition_to(TunnelPhase::ApplyingNetworkConfig);
            }
        }
    }

void TunnelController::Impl::apply_tunnel_config_and_advance() {
        // Use the real IP address assigned by the VPN gateway, falling
        // back to a safe default only when the engine hasn't reported one.
        auto engine_status = runner_.status();
        std::string ip = engine_status.internal_ip;
        assigned_internal_ip_ = ip;
        if (ip.empty()) {
            ip = "10.0.0.2/24";  // safe fallback
        } else if (ip.find('/') == std::string::npos) {
            // The engine reports a bare IP; append a sensible prefix.
            ip += "/24";
        }

        exv::platform::TunnelDeviceDescriptor device;
        if (!prepare_tunnel_device_for_session(&device)) {
            return;
        }
        if (!apply_tunnel_config_for_session(device, ip)) {
            transition_to(TunnelPhase::Failed);
            return;
        }

        // Transition through OpeningPacketDevice and fire
        // NetworkConfigApplied so the state machine advances.
        timing_.timer.start(ConnectTiming::PACKET_DEVICE);
        transition_to(TunnelPhase::OpeningPacketDevice);

        // The engine's packet-loop thread handles the packet device.
        // When it starts, it will fire PacketLoopStarted.
    }

void TunnelController::Impl::on_network_config_applied() {
        if (phase_ == TunnelPhase::ApplyingNetworkConfig) {
            timing_.timer.end(ConnectTiming::NETWORK_CONFIG);
            timing_.timer.start(ConnectTiming::PACKET_DEVICE);
            transition_to(TunnelPhase::OpeningPacketDevice);
        }
    }

void TunnelController::Impl::complete_packet_loop_started() {
        if (phase_ != TunnelPhase::Connected) {
            log_tunnel_event("INFO", "packet.loop.started", "Packet loop started",
                             {{"session_id", session_id_.value}});
            timing_.timer.end(ConnectTiming::PACKET_DEVICE);
            clear_helper_control_plane_error();
            transition_to(TunnelPhase::Connected);
            log_tunnel_event("INFO", "connect.connected", "Tunnel connected",
                             {{"session_id", session_id_.value}});
            reconnect_attempts_ = 0;
            reconnect_policy_.reset();
            start_heartbeat();
        }
    }

void TunnelController::Impl::on_packet_loop_started() {
        packet_loop_started_ = true;
        if (phase_ == TunnelPhase::OpeningPacketDevice) {
            complete_packet_loop_started();
        }
    }

void TunnelController::Impl::on_transport_closed() {
        if (phase_ == TunnelPhase::Reconnecting) {
            return;
        }
        if (phase_ != TunnelPhase::Connected) {
            return;
        }

        stop_heartbeat();

        auto err = CoreErrorMapper::from_transport_error(-1, "transport");

        if (intent_.auto_reconnect) {
            request_recovery("transport_closed", err);
        } else {
            set_error(err);
            transition_to(TunnelPhase::Failed);
        }
    }

void TunnelController::Impl::on_packet_device_failed() {
        if (phase_ != TunnelPhase::OpeningPacketDevice
            && phase_ != TunnelPhase::Connected) {
            return;
        }

        stop_heartbeat();

        auto err = current_native_failure(
            "packet_device_failed",
            "Packet device failed");
        if (err.domain != "packet") {
            err = CoreErrorMapper::from_platform_error(
                "packet", -1, "packet_device");
            err.code = "packet_device_failed";
            err.recoverable = false;
        }

        set_error(err);
        transition_to(TunnelPhase::Failed);
    }

void TunnelController::Impl::on_lease_expired() {
        if (phase_ != TunnelPhase::Connected) {
            return;
        }

        auto err = CoreErrorMapper::from_transport_error(-1, "lease_expired");
        err.code = "lease_expired";
        err.recoverable = true;

        if (intent_.auto_reconnect) {
            request_recovery("lease_expired", err);
        } else {
            set_error(err);
            transition_to(TunnelPhase::Failed);
        }
    }

void TunnelController::Impl::on_reconnect_timer_fired() {
        if (phase_ != TunnelPhase::Reconnecting) {
            return;
        }

        log_tunnel_event(
            "INFO", "reconnect.timer.ignored",
            "Reconnect timer fired after coordinator-owned recovery",
            {{"runtime_epoch", std::to_string(runtime_epoch_)},
             {"controller_id", std::to_string(controller_id_)}});
    }

void TunnelController::Impl::on_helper_lost() {
        // Nothing to lose if we're already idle or failed.
        if (phase_ == TunnelPhase::Idle || phase_ == TunnelPhase::Failed) {
            return;
        }

        stop_heartbeat();
        helper_connected_seen_ = false;
        helper_status_override_ = "unavailable";
        core_lease_id_.clear();
        stop_core_lease_keepalive();

        if (helper_control_plane_loss_is_degradable()) {
            mark_helper_control_plane_degraded(
                "helper_lost",
                "Helper process disconnected unexpectedly");
            return;
        }

        auto err = CoreErrorMapper::from_helper_error(
            "helper_lost", "Helper process disconnected unexpectedly");

        if (intent_.auto_reconnect) {
            request_recovery("helper_lost", err);
            return;
        }

        set_error(err);
        transition_to(TunnelPhase::Failed);
    }

void TunnelController::Impl::on_cleanup_succeeded() {
        transition_to(TunnelPhase::Idle);
    }

void TunnelController::Impl::on_cleanup_failed() {
        // Best-effort: still move to Idle.
        transition_to(TunnelPhase::Idle);
    }

} // namespace exv::core
