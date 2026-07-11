#pragma once
#include "helper/common/helper_messages.hpp"
#include "helper/helper_exit_reason.hpp"
#include "helper/helper_network_ops.hpp"
#include "helper/runtime/helper_request_dispatcher.hpp"
#include "helper/runtime/session_lease_manager.hpp"
#include "helper/runtime/cleanup_registry.hpp"
#include "helper/runtime/helper_lifecycle_policy.hpp"
#include "helper/runtime/command_validator.hpp"
#include "helper/runtime/core_lease_manager.hpp"
#include "helper/runtime/privileged_task_queue.hpp"
#include <memory>
#include <mutex>
#include <optional>

namespace exv::helper {

struct HelperRequestContext {
    HelperPeerIdentity peer;
    bool trusted = false;

    static HelperRequestContext trusted_local() {
        HelperRequestContext context;
        context.trusted = true;
        return context;
    }
};

class HelperHandler {
public:
    explicit HelperHandler(HelperLifecyclePolicy policy = HelperLifecyclePolicy());
    HelperHandler(HelperLifecyclePolicy policy,
                  std::shared_ptr<HelperNetworkOps> network_ops);

    HelperResponse handle(const HelperRequest& request);
    HelperResponse handle(const HelperRequest& request,
                          const HelperRequestContext& context);

    // Periodic maintenance (check timeouts, cleanup stale sessions)
    void tick();

    // Access internals for testing
    SessionLeaseManager& lease_manager();
    CleanupRegistry& cleanup_registry();
    bool should_stop() const;
    bool has_active_core_lease() const;
    std::optional<int> active_core_pid() const;
    void set_startup_context(HelperStartupContext context);
    CleanupResponse cleanup_all_sessions(const CleanupPolicy& policy);
    void handle_core_lifecycle_lost();

    // Record that the daemon is winding down for the given reason. While
    // shutdown_in_progress is set the periodic tick() and core-lease timeout
    // check are no-ops, so a normal caller-driven exit (Shutdown op / service
    // stop / request_daemon_stop) does not race with the heartbeat timer and
    // force a cleanup of sessions the caller is intentionally leaving intact.
    void mark_shutdown(HelperExitReason reason);
    HelperExitReason pending_exit_reason() const;
    bool shutdown_in_progress() const;

private:
    void register_handlers();
    CleanupResponse cleanup_session(const SessionId& session_id,
                                    const CleanupPolicy& policy);
    CleanupResponse cleanup_session_impl(const SessionId& session_id,
                                         const CleanupPolicy& policy);
    CleanupResponse cleanup_all_sessions_for_core_lifecycle();
    bool expire_core_lease_if_needed(std::chrono::steady_clock::time_point now);
    bool is_authorized_for_active_core_lease(
        const HelperRequestContext& context) const;
    CoreLeaseState visible_core_lease_state(
        const HelperRequestContext& context) const;
    HelperMode current_mode() const;
    HelperSessionState current_session_state(
        const HelperRequestContext& context) const;
    std::vector<std::string> capabilities() const;
    TaskQueueState task_queue_state() const;
    HelperResponse core_lease_required_response(HelperOp op) const;
    void bind_core_registry_cleanup_if_possible(const SessionId& session_id);
    void bind_core_registry_cleanup_for_active_sessions();

    HelperResponse handle_hello(const HelperRequest& req,
                                const HelperRequestContext& context);
    HelperResponse handle_start_session(const HelperRequest& req);
    HelperResponse handle_prepare_tunnel_device(const HelperRequest& req);
    HelperResponse handle_apply_tunnel_config(const HelperRequest& req);
    HelperResponse handle_heartbeat(const HelperRequest& req);
    HelperResponse handle_cleanup(const HelperRequest& req);
    HelperResponse handle_get_snapshot(const HelperRequest& req,
                                       const HelperRequestContext& context);
    HelperResponse handle_shutdown(const HelperRequest& req);
    HelperResponse handle_inspect(const HelperRequest& req,
                                  const HelperRequestContext& context);
    HelperResponse handle_acquire_core_lease(
        const HelperRequest& req, const HelperRequestContext& context);
    HelperResponse handle_keep_alive(const HelperRequest& req,
                                     const HelperRequestContext& context);
    HelperResponse handle_release_core_lease(
        const HelperRequest& req, const HelperRequestContext& context);

    HelperRequestDispatcher dispatcher_;
    SessionLeaseManager leases_;
    CoreLeaseManager core_leases_;
    CleanupRegistry cleanup_;
    HelperLifecyclePolicy policy_;
    CommandValidator validator_;
    HelperStartupContext startup_context_;
    std::shared_ptr<HelperNetworkOps> network_ops_;
    bool shutdown_requested_ = false;
    bool shutdown_in_progress_ = false;
    HelperExitReason pending_exit_reason_ = HelperExitReason::Normal;
    mutable std::mutex state_mutex_;
    PrivilegedTaskQueue task_queue_;
};

} // namespace exv::helper
