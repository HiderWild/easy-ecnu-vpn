#include "core/tunnel_controller/tunnel_controller_impl.hpp"

#include <exception>

namespace exv::core {

// ================================================================
// Disconnect flow
// ================================================================

void TunnelController::Impl::close_helper_client_after_terminal_disconnect() {
        if (helper_) {
            try {
                helper_->disconnect();
            } catch (const std::exception& e) {
                log_tunnel_event("WARN", "helper.client.disconnect.failed",
                                 "Helper client disconnect failed",
                                 {{"error", e.what()}});
            }
        }
        helper_connected_seen_ = false;
        helper_status_override_.clear();
        helper_endpoint_.clear();
        helper_mode_ = "unknown";
        update_snapshot();
    }

void TunnelController::Impl::do_disconnect(DisconnectReason reason) {
        intent_.desired_connected    = false;
        intent_.user_disconnect_reason = reason;

        stop_heartbeat();

        // Always stop the native engine session. The monitor thread may have
        // observed a clean packet-loop exit and flipped running_ to false
        // while the session object still owns native resources.
        runner_.stop();

        transition_to(TunnelPhase::Disconnecting);
        do_cleanup();
    }

void TunnelController::Impl::shutdown_helper_session_for_cleanup() {
        try {
            exv::helper::ShutdownRequest req;
            req.session_id = session_id_;
            req.policy.remove_routes       = true;
            req.policy.remove_dns          = true;
            req.policy.remove_adapter      = true;
            req.policy.remove_firewall_rules = true;

            auto resp = helper_->shutdown(req);

            if (!resp.cleanup_success) {
                if (resp.errors.empty()) {
                    log_tunnel_event("WARN", "helper.session.shutdown_partial",
                                     "Helper session shutdown reported partial cleanup");
                }
                for (const auto& error : resp.errors) {
                    log_tunnel_event("WARN", "helper.session.shutdown_partial",
                                     "Helper session shutdown cleanup error",
                                     {{"error", error}});
                }
            }
        } catch (const std::exception&) {
            // Cleanup threw — nothing we can do; finish best effort.
        }

        if (auto delegated_ops = as_helper_delegating_ops(net_ops_)) {
            delegated_ops->clear_session();
        }
        session_id_ = exv::helper::SessionId{};
        assigned_internal_ip_.clear();
        network_config_applied_ = false;
        packet_loop_started_ = false;
        prepared_tunnel_device_.reset();
    }

void TunnelController::Impl::cleanup_after_failed_startup() {
        stop_heartbeat();
        shutdown_helper_session_for_cleanup();
        release_core_lease();
        close_helper_client_after_terminal_disconnect();
    }

void TunnelController::Impl::do_cleanup() {
        stop_heartbeat();
        transition_to(TunnelPhase::CleaningUp);

        shutdown_helper_session_for_cleanup();
        const bool release_ok = release_core_lease();
        close_helper_client_after_terminal_disconnect();
        if (!release_ok) {
            log_tunnel_event("WARN", "core_lease.release.incomplete",
                             "Disconnect completed after best-effort CoreLease release");
        }

        transition_to(TunnelPhase::Idle);
    }

bool TunnelController::Impl::release_core_lease() {
        if (core_lease_id_.empty()) {
            log_tunnel_event("INFO", "core_lease.release.skipped",
                             "No helper core lease to release");
            stop_core_lease_keepalive();
            return true;
        }

        const auto lease_id = core_lease_id_;
        bool released = false;
        try {
            log_tunnel_event("INFO", "core_lease.release.starting",
                             "Releasing helper core lease",
                             {{"lease_id", lease_id}});
            exv::helper::ReleaseCoreLeaseRequest req;
            req.lease_id = lease_id;
            req.exit_if_oneshot = true;
            auto resp = helper_->release_core_lease(req);
            released = resp.released;
            log_tunnel_event("INFO", "core_lease.release.completed",
                             "Helper core lease release completed",
                             {{"released", resp.released ? "true" : "false"},
                              {"exiting", resp.exiting ? "true" : "false"}});
        } catch (const std::exception& e) {
            log_tunnel_event("WARN", "core_lease.release.failed",
                             "Core lease release failed",
                             {{"error", e.what()}});
        }

        core_lease_id_.clear();
        stop_core_lease_keepalive();
        update_snapshot();
        return released;
    }

} // namespace exv::core
