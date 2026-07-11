#include "core/tunnel_controller/tunnel_controller_impl.hpp"

#include <exception>

namespace exv::core {

// ================================================================
// Event handlers (called from on_event)
// ================================================================

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
            attempt_reconnect(err);
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
            attempt_reconnect(err);
        } else {
            set_error(err);
            transition_to(TunnelPhase::Failed);
        }
    }

void TunnelController::Impl::on_reconnect_timer_fired() {
        if (phase_ != TunnelPhase::Reconnecting) {
            return;
        }

        if (!vpn_password_.empty()) {
            scheduler_.cancel_all();
            stop_heartbeat();
            if (core_lease_keepalive_active_) {
                schedule_next_core_lease_keepalive();
            }
            runner_.stop();

            if ((network_config_applied_ || !session_id_.value.empty()) && helper_) {
                shutdown_helper_session_for_cleanup();
            } else {
                if (auto delegated_ops = as_helper_delegating_ops(net_ops_)) {
                    delegated_ops->clear_session();
                }
                session_id_ = exv::helper::SessionId{};
                network_config_applied_ = false;
            }

            do_connect();
            return;
        }

        // Retry the fallback connect flow starting from Authenticating.
        // Tests without native VPN credentials manually drive subsequent events.
        timing_.timer.start(ConnectTiming::AUTH);
        transition_to(TunnelPhase::Authenticating);
    }

void TunnelController::Impl::on_helper_lost() {
        // Nothing to lose if we're already idle or failed.
        if (phase_ == TunnelPhase::Idle || phase_ == TunnelPhase::Failed) {
            return;
        }

        stop_heartbeat();
        helper_connected_seen_ = false;
        helper_status_override_ = "unavailable";

        auto err = CoreErrorMapper::from_helper_error(
            "helper_lost", "Helper process disconnected unexpectedly");

        if (intent_.auto_reconnect) {
            // Reuse the existing helper (the privilege "spark"): reconnect to
            // the same endpoint rather than re-running runas / starting a new
            // one-shot helper. Only if the reconnect fails do we surface Failed.
            try {
                if (helper_ && helper_->connect()) {
                    attempt_reconnect(err);
                    return;
                }
            } catch (...) {
                // Helper reconnection failed — fall through.
            }
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
