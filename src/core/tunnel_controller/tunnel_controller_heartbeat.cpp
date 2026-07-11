#include "core/tunnel_controller/tunnel_controller_impl.hpp"

#include <exception>

namespace exv::core {

// ================================================================
// Heartbeat — keeps the helper session alive
// ================================================================

void TunnelController::Impl::start_heartbeat() {
        if (heartbeat_active_) return;
        if (!helper_ || !helper_->is_connected()) return;
        heartbeat_active_ = true;
        do_heartbeat();
    }

void TunnelController::Impl::stop_heartbeat() {
        heartbeat_active_ = false;
        // No need to cancel scheduler — the callback checks heartbeat_active_.
    }

void TunnelController::Impl::schedule_next_heartbeat() {
        if (!heartbeat_active_) return;
        scheduler_.schedule(kHeartbeatInterval, [this] {
            do_heartbeat();
        });
    }

void TunnelController::Impl::do_heartbeat() {
        if (!heartbeat_active_) return;
        if (!helper_ || !helper_->is_connected()) {
            stop_heartbeat();
            return;
        }

        try {
            exv::helper::HeartbeatRequest req;
            req.session_id = session_id_;
            // Map current phase to a string the helper understands.
            switch (phase_) {
                case TunnelPhase::PreparingHelper: req.core_phase = "PreparingHelper"; break;
                case TunnelPhase::Connected:     req.core_phase = "Connected"; break;
                case TunnelPhase::Reconnecting:  req.core_phase = "Reconnecting"; break;
                case TunnelPhase::Authenticating: req.core_phase = "Authenticating"; break;
                case TunnelPhase::ConnectingCstp: req.core_phase = "ConnectingCstp"; break;
                case TunnelPhase::ApplyingNetworkConfig: req.core_phase = "ApplyingNetworkConfig"; break;
                case TunnelPhase::OpeningPacketDevice: req.core_phase = "OpeningPacketDevice"; break;
                default:                          req.core_phase = "Idle"; break;
            }

            auto resp = helper_->heartbeat(req);
            if (!resp.ok) {
                log_tunnel_event("WARN", "heartbeat.failed",
                                 "Heartbeat response not ok",
                                 {{"warning", resp.warning.value_or("")}});
            }
        } catch (const std::exception& e) {
            log_tunnel_event("ERROR", "heartbeat.error",
                             "Heartbeat send failed",
                             {{"error", e.what()}});
            stop_heartbeat();
            // Don't fire HelperLost here — let the next actual helper
            // operation detect the disconnection naturally.
            return;
        }

        // Schedule the next heartbeat.
        schedule_next_heartbeat();
    }

void TunnelController::Impl::start_core_lease_keepalive() {
        if (core_lease_keepalive_active_) return;
        if (core_lease_id_.empty()) return;
        core_lease_keepalive_active_ = true;
        do_core_lease_keepalive();
    }

void TunnelController::Impl::stop_core_lease_keepalive() {
        core_lease_keepalive_active_ = false;
}

void TunnelController::Impl::schedule_next_core_lease_keepalive() {
        if (!core_lease_keepalive_active_) return;
        scheduler_.schedule(kCoreLeaseKeepAliveInterval, [this] {
            do_core_lease_keepalive();
        });
}

void TunnelController::Impl::do_core_lease_keepalive() {
        if (!core_lease_keepalive_active_) return;
        if (!helper_ || core_lease_id_.empty()) {
            stop_core_lease_keepalive();
            return;
        }

        auto finish_core_lease_keepalive_failure =
            [this](const std::string& warning) {
            const bool degradable =
                helper_control_plane_loss_is_degradable();
            mark_helper_control_plane_degraded(
                "core_lease_keepalive", warning);
            log_tunnel_event(
                "WARN", "core_lease.keep_alive.degraded",
                degradable
                    ? "Core lease keepalive failed while VPN session can continue"
                    : "Core lease keepalive failed before VPN session was established",
                {{"warning", warning},
                 {"phase", tunnel_phase_wire_name(phase_)},
                 {"session_active", snapshot_.session_active ? "true" : "false"},
                 {"network_ready", snapshot_.network_ready ? "true" : "false"},
                 {"last_error",
                  snapshot_.last_error.has_value() ? snapshot_.last_error->code
                                                   : ""}});
        };

        auto terminate_core_lease_keepalive =
            [&finish_core_lease_keepalive_failure](const std::string& warning) {
            log_tunnel_event("WARN", "core_lease.keep_alive.failed",
                             "Core lease keepalive response not ok",
                             {{"warning", warning}});
            finish_core_lease_keepalive_failure(warning);
        };

        if (!helper_->is_connected()) {
            terminate_core_lease_keepalive("PipeHelperClient is not connected");
            return;
        }

        try {
            exv::helper::KeepAliveRequest req;
            req.lease_id = core_lease_id_;
            req.state = tunnel_phase_wire_name(phase_);

            auto resp = helper_->keep_alive(req);
            if (!resp.ok) {
                terminate_core_lease_keepalive(resp.warning.value_or(""));
                return;
            }
        } catch (const std::exception& e) {
            log_tunnel_event("ERROR", "core_lease.keep_alive.error",
                             "Core lease keepalive send failed",
                             {{"error", e.what()}});
            finish_core_lease_keepalive_failure(e.what());
            return;
        }

        schedule_next_core_lease_keepalive();
    }

} // namespace exv::core
