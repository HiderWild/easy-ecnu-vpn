#include "helper/helper_handler.hpp"
#include "core/lifecycle/core_paths.hpp"
#include "core/lifecycle/core_registry.hpp"
#include "observability/log_facade.hpp"

#include <nlohmann/json.hpp>
#include <sstream>
#include <utility>

namespace exv::helper {

namespace {

bool is_oneshot_context(const HelperStartupContext& context) {
    return context.launch_mode == "oneshot";
}

bool requires_core_lease(HelperOp op) {
    switch (op) {
        case HelperOp::StartSession:
        case HelperOp::PrepareTunnelDevice:
        case HelperOp::ApplyTunnelConfig:
        case HelperOp::Heartbeat:
        case HelperOp::Cleanup:
        case HelperOp::Shutdown:
            return true;
        case HelperOp::Hello:
        case HelperOp::GetSnapshot:
        case HelperOp::Inspect:
        case HelperOp::AcquireCoreLease:
        case HelperOp::KeepAlive:
        case HelperOp::ReleaseCoreLease:
            return false;
    }
    return false;
}

HelperResponse make_error_response(HelperOp op, const std::string& code,
                                   const std::string& message) {
    HelperResponse resp;
    resp.op = op;
    resp.success = false;
    resp.error_code = code;
    resp.error_message = message;
    return resp;
}

} // namespace

HelperHandler::HelperHandler(HelperLifecyclePolicy policy)
    : HelperHandler(std::move(policy), nullptr) {
}

HelperHandler::HelperHandler(HelperLifecyclePolicy policy,
                             std::shared_ptr<HelperNetworkOps> network_ops)
    : policy_(std::move(policy)),
      network_ops_(std::move(network_ops)) {
    register_handlers();
}

void HelperHandler::register_handlers() {
    dispatcher_.register_handler(HelperOp::Hello,
        [this](const HelperRequest& req, const HelperRequestContext& context) {
            return handle_hello(req, context);
        });
    dispatcher_.register_handler(HelperOp::StartSession,
        [this](const HelperRequest& req, const HelperRequestContext&) {
            return handle_start_session(req);
        });
    dispatcher_.register_handler(HelperOp::PrepareTunnelDevice,
        [this](const HelperRequest& req, const HelperRequestContext&) {
            return handle_prepare_tunnel_device(req);
        });
    dispatcher_.register_handler(HelperOp::ApplyTunnelConfig,
        [this](const HelperRequest& req, const HelperRequestContext&) {
            return handle_apply_tunnel_config(req);
        });
    dispatcher_.register_handler(HelperOp::Heartbeat,
        [this](const HelperRequest& req, const HelperRequestContext&) {
            return handle_heartbeat(req);
        });
    dispatcher_.register_handler(HelperOp::Cleanup,
        [this](const HelperRequest& req, const HelperRequestContext&) {
            return handle_cleanup(req);
        });
    dispatcher_.register_handler(HelperOp::GetSnapshot,
        [this](const HelperRequest& req, const HelperRequestContext& context) {
            return handle_get_snapshot(req, context);
        });
    dispatcher_.register_handler(HelperOp::Shutdown,
        [this](const HelperRequest& req, const HelperRequestContext&) {
            return handle_shutdown(req);
        });
    dispatcher_.register_handler(HelperOp::Inspect,
        [this](const HelperRequest& req, const HelperRequestContext& context) {
            return handle_inspect(req, context);
        });
    dispatcher_.register_handler(HelperOp::AcquireCoreLease,
        [this](const HelperRequest& req, const HelperRequestContext& context) {
            return handle_acquire_core_lease(req, context);
        });
    dispatcher_.register_handler(HelperOp::KeepAlive,
        [this](const HelperRequest& req, const HelperRequestContext& context) {
            return handle_keep_alive(req, context);
        });
    dispatcher_.register_handler(HelperOp::ReleaseCoreLease,
        [this](const HelperRequest& req, const HelperRequestContext& context) {
            return handle_release_core_lease(req, context);
        });
}

HelperResponse HelperHandler::handle(const HelperRequest& request) {
    return handle(request, HelperRequestContext::trusted_local());
}

HelperResponse HelperHandler::handle(const HelperRequest& request,
                                     const HelperRequestContext& context) {
    auto validation_error = validator_.validate(request);
    if (validation_error.has_value()) {
        HelperResponse resp;
        resp.op = request.op;
        resp.success = false;
        resp.error_code = std::to_string(static_cast<int>(validation_error->code));
        resp.error_message = validation_error->message;
        return resp;
    }

    expire_core_lease_if_needed(std::chrono::steady_clock::now());

    const bool core_lease_required = requires_core_lease(request.op);
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (core_lease_required && !core_leases_.has_active_lease()) {
            return core_lease_required_response(request.op);
        }
        if (core_lease_required && !is_authorized_for_active_core_lease(context)) {
            return make_error_response(request.op, "core_lease_unauthorized",
                                       "Request is not bound to the active core lease");
        }
        if (core_lease_required) {
            core_leases_.mark_activity("privileged_request_active");
        }
    }

    HelperResponse response = dispatcher_.dispatch(request, context);
    if (core_lease_required) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        core_leases_.mark_activity("privileged_request_complete");
    }
    return response;
}

void HelperHandler::tick() {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (shutdown_in_progress_) {
            // A caller-driven shutdown is in flight; do not let the timeout
            // path force a cleanup of sessions the caller is winding down on
            // its own terms.
            return;
        }
    }
    auto now = std::chrono::steady_clock::now();

    if (expire_core_lease_if_needed(now)) {
        return;
    }

    std::vector<SessionId> stale_ids;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        auto active_ids = leases_.active_session_ids();
        for (const auto& id : active_ids) {
            auto lease = leases_.get_session(id);
            if (lease.has_value() && policy_.should_cleanup_stale(*lease, now)) {
                stale_ids.push_back(id);
            }
        }
    }

    for (const auto& id : stale_ids) {
        exv::observability::LogFacade::info("[helper] Heartbeat timed out; cleaning session: "
                              + id.value);
        CleanupPolicy full_policy;
        full_policy.remove_routes = true;
        full_policy.remove_dns = true;
        full_policy.remove_adapter = true;
        full_policy.remove_firewall_rules = true;
        CleanupResponse cleanup_resp = cleanup_session(id, full_policy);
        if (cleanup_resp.success) {
            std::lock_guard<std::mutex> lock(state_mutex_);
            if (is_oneshot_context(startup_context_) &&
                !core_leases_.has_active_lease()) {
                shutdown_requested_ = true;
                shutdown_in_progress_ = true;
                pending_exit_reason_ = HelperExitReason::Timeout;
            }
        }
    }
}

SessionLeaseManager& HelperHandler::lease_manager() {
    return leases_;
}

CleanupRegistry& HelperHandler::cleanup_registry() {
    return cleanup_;
}

bool HelperHandler::should_stop() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return shutdown_requested_;
}

bool HelperHandler::has_active_core_lease() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return core_leases_.has_active_lease();
}

std::optional<int> HelperHandler::active_core_pid() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto lease = core_leases_.active_lease();
    if (!lease.has_value()) {
        return std::nullopt;
    }
    return lease->core_pid;
}

void HelperHandler::set_startup_context(HelperStartupContext context) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    startup_context_ = std::move(context);
}

void HelperHandler::mark_shutdown(HelperExitReason reason) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    shutdown_in_progress_ = true;
    pending_exit_reason_ = reason;
}

HelperExitReason HelperHandler::pending_exit_reason() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return pending_exit_reason_;
}

bool HelperHandler::shutdown_in_progress() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return shutdown_in_progress_;
}

CleanupResponse HelperHandler::cleanup_all_sessions(const CleanupPolicy& policy) {
    CleanupResponse aggregate;
    aggregate.success = true;
    std::vector<SessionId> active_ids;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        active_ids = leases_.active_session_ids();
    }
    for (const auto& id : active_ids) {
        CleanupResponse cleanup_resp = cleanup_session(id, policy);
        if (!cleanup_resp.success) {
            aggregate.success = false;
            aggregate.errors.insert(aggregate.errors.end(),
                                    cleanup_resp.errors.begin(),
                                    cleanup_resp.errors.end());
        }
    }
    return aggregate;
}

void HelperHandler::handle_core_lifecycle_lost() {
    CleanupResponse cleanup_resp = cleanup_all_sessions_for_core_lifecycle();
    if (!cleanup_resp.success) {
        return;
    }
    std::lock_guard<std::mutex> lock(state_mutex_);
    core_leases_.clear();
    if (is_oneshot_context(startup_context_)) {
        shutdown_requested_ = true;
        shutdown_in_progress_ = true;
        pending_exit_reason_ = HelperExitReason::Timeout;
    }
}

CleanupResponse HelperHandler::cleanup_all_sessions_for_core_lifecycle() {
    CleanupPolicy full_policy;
    full_policy.remove_routes = true;
    full_policy.remove_dns = true;
    full_policy.remove_adapter = true;
    full_policy.remove_firewall_rules = true;
    return cleanup_all_sessions(full_policy);
}

bool HelperHandler::expire_core_lease_if_needed(
    std::chrono::steady_clock::time_point now) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (shutdown_in_progress_) {
            return false;
        }
    }
    if (!task_queue_.state().idle) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        core_leases_.mark_activity("privileged_task_busy");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        auto core_lease = core_leases_.active_lease();
        if (!core_lease.has_value() ||
            !policy_.is_core_lease_expired(core_lease->last_seen, now)) {
            return false;
        }
    }

    exv::observability::LogFacade::info(
        "[helper] Core lease timed out; cleaning active sessions");
    CleanupResponse cleanup_resp = cleanup_all_sessions_for_core_lifecycle();
    if (cleanup_resp.success) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        core_leases_.clear();
        if (is_oneshot_context(startup_context_)) {
            shutdown_requested_ = true;
            shutdown_in_progress_ = true;
            pending_exit_reason_ = HelperExitReason::Timeout;
        }
    }
    return true;
}

bool HelperHandler::is_authorized_for_active_core_lease(
    const HelperRequestContext& context) const {
    return context.trusted || core_leases_.peer_matches(context.peer);
}

CoreLeaseState HelperHandler::visible_core_lease_state(
    const HelperRequestContext& context) const {
    CoreLeaseState state = core_leases_.state();
    if (!state.active || is_authorized_for_active_core_lease(context)) {
        return state;
    }

    CoreLeaseState redacted;
    redacted.active = true;
    return redacted;
}

HelperMode HelperHandler::current_mode() const {
    return (startup_context_.launch_mode == "service" ||
            startup_context_.launch_mode == "resident")
               ? HelperMode::Resident
               : HelperMode::Transient;
}

std::vector<std::string> HelperHandler::capabilities() const {
    return {"session", "heartbeat", "cleanup", "snapshot", "shutdown",
            "inspect", "core_lease", "service_install",
            "service_uninstall", "service_repair"};
}

HelperSessionState HelperHandler::current_session_state(
    const HelperRequestContext& context) const {
    HelperSessionState state;
    auto active_ids = leases_.active_session_ids();
    if (active_ids.empty()) {
        return state;
    }

    if (core_leases_.has_active_lease() &&
        !is_authorized_for_active_core_lease(context)) {
        state.active = true;
        return state;
    }

    auto lease = leases_.get_session(active_ids.front());
    if (!lease.has_value()) {
        return state;
    }

    state.active = true;
    state.session_id = lease->session_id;
    state.core_phase = lease->core_phase;
    return state;
}

HelperResponse HelperHandler::core_lease_required_response(HelperOp op) const {
    return make_error_response(op, "core_lease_required",
                               "An active core lease is required");
}

TaskQueueState HelperHandler::task_queue_state() const {
    return task_queue_.state();
}

void HelperHandler::bind_core_registry_cleanup_if_possible(
    const SessionId& session_id) {
    std::string active_lease_id;
    int active_core_pid = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!leases_.has_session(session_id)) {
            return;
        }
        const auto active_lease = core_leases_.active_lease();
        if (!active_lease.has_value()) {
            return;
        }
        active_lease_id = active_lease->lease_id;
        active_core_pid = active_lease->core_pid;
    }

    const auto registry_path = exv::core::lifecycle::core_registry_path();
    const auto loaded =
        exv::core::lifecycle::read_core_registry(registry_path);
    if (loaded.state != exv::core::lifecycle::CoreRegistryReadState::present ||
        !loaded.snapshot.has_value()) {
        return;
    }

    const auto& snapshot = *loaded.snapshot;
    if (snapshot.helper_core_lease_id.empty() ||
        snapshot.helper_core_lease_id != active_lease_id ||
        snapshot.pid != active_core_pid ||
        snapshot.ipc_protocol_version !=
            exv::core::lifecycle::ipc_protocol_name()) {
        return;
    }

    CoreRegistryCleanupBinding binding;
    binding.registry_path = registry_path;
    binding.delete_match =
        exv::core::lifecycle::core_registry_delete_match(snapshot);

    std::lock_guard<std::mutex> lock(state_mutex_);
    if (!leases_.has_session(session_id)) {
        return;
    }
    const auto active_lease = core_leases_.active_lease();
    if (!active_lease.has_value() ||
        active_lease->lease_id != active_lease_id ||
        active_lease->core_pid != active_core_pid) {
        return;
    }
    cleanup_.bind_core_registry_cleanup(session_id, binding);
}

void HelperHandler::bind_core_registry_cleanup_for_active_sessions() {
    std::vector<SessionId> active_sessions;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        active_sessions = leases_.active_session_ids();
    }
    for (const auto& session_id : active_sessions) {
        bind_core_registry_cleanup_if_possible(session_id);
    }
}

// --- Handler implementations ---

HelperResponse HelperHandler::handle_hello(
    const HelperRequest& req, const HelperRequestContext& context) {
    HelloResponse hello;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        hello.capabilities = capabilities();
        hello.mode = current_mode();
        hello.startup_context = startup_context_;
        hello.session_state = current_session_state(context);
        hello.core_lease = visible_core_lease_state(context);
    }
    hello.task_queue = task_queue_state();

    nlohmann::json payload;
    to_json(payload, hello);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_start_session(const HelperRequest& req) {
    StartSessionRequest start_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        if (j.contains("native_start_mode") || j.contains("supervisor_payload") ||
            j.contains("supervisor_start") || j.contains("vpn_supervisor")) {
            return make_error_response(
                req.op, "supervisor_removed",
                "VPN supervisor startup has been removed; use TunnelController.");
        }
        start_req = start_session_request_from_json(j);
    } catch (const std::exception& e) {
        HelperResponse resp;
        resp.op = req.op;
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = std::string("Failed to parse StartSession request: ") + e.what();
        return resp;
    }

    SessionId session_id;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);

        if (leases_.active_session_count() > 0) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "session_conflict";
            resp.error_message = "An active helper session already exists";
            return resp;
        }

        CleanupPolicy default_policy;
        session_id = leases_.create_session(
            start_req.profile_id, start_req.mode, default_policy);

        // Register a cleanup record for the new session
        CleanupRecord record;
        record.session_id = session_id;
        record.created_at = std::chrono::system_clock::now();
        cleanup_.register_session(record);
    }

    bind_core_registry_cleanup_if_possible(session_id);

    exv::observability::LogFacade::info("[helper] Session started: " + session_id.value);

    StartSessionResponse start_resp;
    start_resp.session_id = session_id;

    nlohmann::json payload;
    to_json(payload, start_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_prepare_tunnel_device(const HelperRequest& req) {
    PrepareTunnelDeviceRequest device_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        device_req = prepare_tunnel_device_request_from_json(j);
    } catch (const std::exception& e) {
        HelperResponse resp;
        resp.op = req.op;
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = std::string("Failed to parse PrepareTunnelDevice request: ") + e.what();
        return resp;
    }

    std::shared_ptr<HelperNetworkOps> network_ops;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!leases_.has_session(device_req.session_id)) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "invalid_session";
            resp.error_message = "Session not found: " + device_req.session_id.value;
            return resp;
        }

        network_ops = network_ops_;
        if (!network_ops) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "network_ops_unavailable";
            resp.error_message = "Helper network operations are not available";
            return resp;
        }
    }

    PrepareTunnelDeviceResponse device_resp = task_queue_.run_sync(
        "prepare_tunnel_device", [this, device_req, network_ops] {
            std::vector<ManagedResource> created_resources;
            PrepareTunnelDeviceResponse response =
                network_ops->prepare_tunnel_device(device_req, &created_resources);
            bool still_active = false;
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                still_active = leases_.has_session(device_req.session_id);
                if (still_active) {
                    for (const auto& resource : created_resources) {
                        cleanup_.add_resource(device_req.session_id, resource);
                    }
                }
            }
            if (!still_active && !created_resources.empty()) {
                CleanupPolicy policy;
                policy.remove_routes = true;
                policy.remove_dns = true;
                policy.remove_adapter = true;
                policy.remove_firewall_rules = true;
                (void)network_ops->cleanup(device_req.session_id, policy,
                                           created_resources);
                response.device_path.clear();
            }
            return response;
        });

    nlohmann::json payload;
    to_json(payload, device_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = !device_resp.device_path.empty();
    if (!resp.success) {
        resp.error_code = device_resp.error_code.empty()
                              ? "device_not_found"
                              : device_resp.error_code;
        resp.error_message = device_resp.error_message.empty()
                                 ? "Helper network operations did not return a device"
                                 : device_resp.error_message;
    }
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_apply_tunnel_config(const HelperRequest& req) {
    ApplyTunnelConfigRequest config_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        config_req = apply_tunnel_config_request_from_json(j);
    } catch (const std::exception& e) {
        HelperResponse resp;
        resp.op = req.op;
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = std::string("Failed to parse ApplyTunnelConfig request: ") + e.what();
        return resp;
    }

    std::shared_ptr<HelperNetworkOps> network_ops;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!leases_.has_session(config_req.config.session_id)) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "invalid_session";
            resp.error_message = "Session not found: " + config_req.config.session_id.value;
            return resp;
        }

        network_ops = network_ops_;
        if (!network_ops) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "network_ops_unavailable";
            resp.error_message = "Helper network operations are not available";
            return resp;
        }
    }

    ApplyTunnelConfigResponse config_resp = task_queue_.run_sync(
        "apply_tunnel_config", [this, config_req, network_ops] {
            std::vector<ManagedResource> created_resources;
            ApplyTunnelConfigResponse response =
                network_ops->apply_tunnel_config(config_req, &created_resources);
            if (response.success) {
                bool still_active = false;
                {
                    std::lock_guard<std::mutex> lock(state_mutex_);
                    still_active =
                        leases_.has_session(config_req.config.session_id);
                    if (still_active) {
                        for (const auto& resource : created_resources) {
                            cleanup_.add_resource(config_req.config.session_id,
                                                  resource);
                        }
                    }
                }
                if (!still_active && !created_resources.empty()) {
                    CleanupPolicy policy;
                    policy.remove_routes = true;
                    policy.remove_dns = true;
                    policy.remove_adapter = true;
                    policy.remove_firewall_rules = true;
                    (void)network_ops->cleanup(config_req.config.session_id,
                                               policy, created_resources);
                    response.success = false;
                    response.error_code = "session_cleaned_during_apply";
                    response.error_message =
                        "Session was cleaned before apply completed";
                }
            }
            return response;
        }
    );

    nlohmann::json payload;
    to_json(payload, config_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = config_resp.success;
    if (!resp.success) {
        resp.error_code = config_resp.error_code.empty()
                              ? "network_ops_failed"
                              : config_resp.error_code;
        resp.error_message = config_resp.error_message.empty()
                                 ? "Helper network operations failed"
                                 : config_resp.error_message;
    }
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_heartbeat(const HelperRequest& req) {
    HeartbeatRequest hb_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        hb_req = heartbeat_request_from_json(j);
    } catch (const std::exception& e) {
        HelperResponse resp;
        resp.op = req.op;
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = std::string("Failed to parse Heartbeat request: ") + e.what();
        return resp;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!leases_.has_session(hb_req.session_id)) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "invalid_session";
            resp.error_message = "Session not found: " + hb_req.session_id.value;
            return resp;
        }

        leases_.update_heartbeat(hb_req.session_id, hb_req.core_phase);
    }

    bind_core_registry_cleanup_if_possible(hb_req.session_id);

    // Check if heartbeat indicates a concerning phase
    std::optional<std::string> warning;
    if (hb_req.core_phase == "error" || hb_req.core_phase == "disconnecting") {
        warning = "Core reported phase: " + hb_req.core_phase;
    }

    HeartbeatResponse hb_resp;
    hb_resp.ok = true;
    hb_resp.warning = warning;

    nlohmann::json payload;
    to_json(payload, hb_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

CleanupResponse HelperHandler::cleanup_session(const SessionId& session_id,
                                               const CleanupPolicy& policy) {
    return task_queue_.run_sync("cleanup_session", [this, session_id, policy] {
        return cleanup_session_impl(session_id, policy);
    });
}

CleanupResponse HelperHandler::cleanup_session_impl(const SessionId& session_id,
                                                    const CleanupPolicy& policy) {
    std::vector<ManagedResource> resources;
    std::shared_ptr<HelperNetworkOps> network_ops;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        resources = cleanup_.get_resources(session_id);
        network_ops = network_ops_;
    }
    std::vector<std::string> errors;

    for (const auto& res : resources) {
        exv::observability::LogFacade::info("[helper] Cleaning managed resource: type=" + res.type
                              + " detail=" + res.detail);
    }
    if (!resources.empty() && !network_ops) {
        (void)policy;
        errors.push_back("Platform cleanup operations are not available");
        CleanupResponse cleanup_resp;
        cleanup_resp.success = false;
        cleanup_resp.errors = errors;
        return cleanup_resp;
    }
    if (!resources.empty()) {
        CleanupResponse cleanup_resp =
            network_ops->cleanup(session_id, policy, resources);
        if (!cleanup_resp.success) {
            return cleanup_resp;
        }
    }

    std::optional<CoreRegistryCleanupBinding> registry_cleanup;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        registry_cleanup = cleanup_.core_registry_cleanup_binding(session_id);
    }

    if (registry_cleanup.has_value() &&
        !exv::core::lifecycle::compare_and_delete_core_registry(
            registry_cleanup->registry_path, registry_cleanup->delete_match)) {
        CleanupResponse cleanup_resp;
        cleanup_resp.success = false;
        cleanup_resp.errors.push_back(
            "Core registry cleanup could not remove the versioned registry");
        return cleanup_resp;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        cleanup_.remove_session(session_id);
        leases_.remove_session(session_id);
    }

    CleanupResponse cleanup_resp;
    cleanup_resp.success = errors.empty();
    cleanup_resp.errors = errors;
    return cleanup_resp;
}

HelperResponse HelperHandler::handle_cleanup(const HelperRequest& req) {
    CleanupRequest cleanup_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        cleanup_req = cleanup_request_from_json(j);
    } catch (const std::exception& e) {
        HelperResponse resp;
        resp.op = req.op;
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = std::string("Failed to parse Cleanup request: ") + e.what();
        return resp;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!leases_.has_session(cleanup_req.session_id)) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "invalid_session";
            resp.error_message = "Session not found: " + cleanup_req.session_id.value;
            return resp;
        }
    }

    exv::observability::LogFacade::info("[helper] Cleaning up session: " + cleanup_req.session_id.value);

    CleanupResponse cleanup_resp =
        cleanup_session(cleanup_req.session_id, cleanup_req.policy);

    nlohmann::json payload;
    to_json(payload, cleanup_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = cleanup_resp.success;
    if (!cleanup_resp.success) {
        resp.error_code = "cleanup_partial";
        resp.error_message = "Cleanup could not remove all managed resources";
    }
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_get_snapshot(
    const HelperRequest& /*req*/, const HelperRequestContext& context) {
    GetSnapshotResponse snap_resp;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (core_leases_.has_active_lease() &&
            !is_authorized_for_active_core_lease(context)) {
            return make_error_response(HelperOp::GetSnapshot,
                                       "core_lease_unauthorized",
                                       "Snapshot is bound to the active core lease");
        }

        auto records = cleanup_.all_records();
        for (const auto& record : records) {
            auto lease = leases_.get_session(record.session_id);
            if (!lease.has_value()) continue;

            SessionSnapshot snap;
            snap.session_id = record.session_id;
            snap.core_phase = lease->core_phase;
            snap.last_heartbeat = lease->last_heartbeat;

            auto resources = cleanup_.get_resources(record.session_id);
            for (const auto& res : resources) {
                snap.managed_resources.push_back(res.type + ":" + res.detail);
            }

            snap_resp.sessions.push_back(std::move(snap));
        }
    }

    nlohmann::json payload;
    to_json(payload, snap_resp);

    HelperResponse resp;
    resp.op = HelperOp::GetSnapshot;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_shutdown(const HelperRequest& req) {
    ShutdownRequest shutdown_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        shutdown_req = shutdown_request_from_json(j);
    } catch (const std::exception& e) {
        HelperResponse resp;
        resp.op = req.op;
        resp.success = false;
        resp.error_code = "invalid_payload";
        resp.error_message = std::string("Failed to parse Shutdown request: ") + e.what();
        return resp;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!leases_.has_session(shutdown_req.session_id)) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "invalid_session";
            resp.error_message = "Session not found: " + shutdown_req.session_id.value;
            return resp;
        }
    }

    exv::observability::LogFacade::info("[helper] Shutting down session: " + shutdown_req.session_id.value);

    CleanupResponse cleanup_resp =
        cleanup_session(shutdown_req.session_id, shutdown_req.policy);

    ShutdownResponse shutdown_resp;
    shutdown_resp.cleanup_success = cleanup_resp.success;
    shutdown_resp.errors = cleanup_resp.errors;
    shutdown_resp.exiting = false;

    nlohmann::json payload;
    to_json(payload, shutdown_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = cleanup_resp.success;
    if (!cleanup_resp.success) {
        resp.error_code = "cleanup_partial";
        resp.error_message = "Shutdown cleanup could not remove all managed resources";
    }
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_inspect(
    const HelperRequest& req, const HelperRequestContext& context) {
    InspectResponse inspect;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        inspect.capabilities = capabilities();
        inspect.mode = current_mode();
        inspect.startup_context = startup_context_;
        inspect.session_state = current_session_state(context);
        inspect.core_lease = visible_core_lease_state(context);
    }
    inspect.task_queue = task_queue_state();

    nlohmann::json payload;
    to_json(payload, inspect);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_acquire_core_lease(
    const HelperRequest& req, const HelperRequestContext& context) {
    AcquireCoreLeaseRequest acquire_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        acquire_req = acquire_core_lease_request_from_json(j);
    } catch (const std::exception& e) {
        return make_error_response(
            req.op, "invalid_payload",
            std::string("Failed to parse AcquireCoreLease request: ") + e.what());
    }

    if (acquire_req.core_pid <= 0 || acquire_req.purpose.empty()) {
        return make_error_response(req.op, "invalid_core_lease_request",
                                   "AcquireCoreLease requires core_pid and purpose");
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!context.trusted) {
            if (!context.peer.verified) {
                return make_error_response(req.op, "core_lease_unauthorized",
                                           "AcquireCoreLease requires a verified peer");
            }
            if (context.peer.pid > 0 && acquire_req.core_pid != context.peer.pid) {
                return make_error_response(req.op, "core_lease_unauthorized",
                                           "AcquireCoreLease core_pid does not match peer process");
            }
            if (is_oneshot_context(startup_context_) &&
                !startup_context_.owner.empty()) {
                const bool owner_matches =
                    (!context.peer.owner.empty() &&
                     context.peer.owner == startup_context_.owner) ||
                    std::to_string(context.peer.uid) == startup_context_.owner;
                if (!owner_matches) {
                    return make_error_response(req.op, "core_lease_unauthorized",
                                               "AcquireCoreLease peer owner does not match helper owner");
                }
            }
        }

        if (core_leases_.has_active_lease()) {
            return make_error_response(req.op, "core_lease_conflict",
                                       "An active core lease already exists");
        }

        HelperPeerIdentity peer = context.peer;
        if (context.trusted && !peer.verified) {
            peer.verified = true;
            peer.owner = "trusted-local";
            peer.pid = acquire_req.core_pid;
        }

        if (!core_leases_.acquire(acquire_req.core_pid, acquire_req.purpose, peer)) {
            return make_error_response(req.op, "invalid_core_lease_request",
                                       "AcquireCoreLease could not be accepted");
        }
    }

    AcquireCoreLeaseResponse acquire_resp;
    acquire_resp.accepted = true;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        acquire_resp.lease_id = core_leases_.state().lease_id;
        acquire_resp.mode = startup_context_.launch_mode.empty()
                                ? (current_mode() == HelperMode::Resident ? "service" : "oneshot")
                                : startup_context_.launch_mode;
    }

    nlohmann::json payload;
    to_json(payload, acquire_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_keep_alive(
    const HelperRequest& req, const HelperRequestContext& context) {
    KeepAliveRequest keep_alive_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        keep_alive_req = keep_alive_request_from_json(j);
    } catch (const std::exception& e) {
        return make_error_response(
            req.op, "invalid_payload",
            std::string("Failed to parse KeepAlive request: ") + e.what());
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!is_authorized_for_active_core_lease(context)) {
            return make_error_response(req.op, "core_lease_unauthorized",
                                       "KeepAlive is not bound to the active core lease");
        }

        if (!core_leases_.keep_alive(keep_alive_req.lease_id,
                                     keep_alive_req.state)) {
            return make_error_response(req.op, "invalid_core_lease",
                                       "KeepAlive lease_id does not match active core lease");
        }
    }

    bind_core_registry_cleanup_for_active_sessions();

    KeepAliveResponse keep_alive_resp;
    keep_alive_resp.ok = true;

    nlohmann::json payload;
    to_json(payload, keep_alive_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

HelperResponse HelperHandler::handle_release_core_lease(
    const HelperRequest& req, const HelperRequestContext& context) {
    ReleaseCoreLeaseRequest release_req;
    try {
        auto j = nlohmann::json::parse(req.payload_json);
        release_req = release_core_lease_request_from_json(j);
    } catch (const std::exception& e) {
        return make_error_response(
            req.op, "invalid_payload",
            std::string("Failed to parse ReleaseCoreLease request: ") + e.what());
    }

    bool exiting = false;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!is_authorized_for_active_core_lease(context)) {
            return make_error_response(req.op, "core_lease_unauthorized",
                                       "ReleaseCoreLease is not bound to the active core lease");
        }

        exiting =
            release_req.exit_if_oneshot && is_oneshot_context(startup_context_);
    }
    if (exiting) {
        CleanupResponse cleanup_resp = cleanup_all_sessions_for_core_lifecycle();
        if (!cleanup_resp.success) {
            HelperResponse resp;
            resp.op = req.op;
            resp.success = false;
            resp.error_code = "cleanup_partial";
            resp.error_message =
                "ReleaseCoreLease cleanup could not remove all managed resources";
            nlohmann::json payload = nlohmann::json{{"released", false},
                                                     {"exiting", false}};
            resp.payload_json = payload.dump();
            return resp;
        }
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (!core_leases_.release(release_req.lease_id)) {
            return make_error_response(req.op, "invalid_core_lease",
                                       "ReleaseCoreLease lease_id does not match active core lease");
        }
    }

    ReleaseCoreLeaseResponse release_resp;
    release_resp.released = true;
    release_resp.exiting = exiting;
    if (release_resp.exiting) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        shutdown_requested_ = true;
        shutdown_in_progress_ = true;
        pending_exit_reason_ = HelperExitReason::Normal;
    }

    nlohmann::json payload;
    to_json(payload, release_resp);

    HelperResponse resp;
    resp.op = req.op;
    resp.success = true;
    resp.payload_json = payload.dump();
    return resp;
}

} // namespace exv::helper
