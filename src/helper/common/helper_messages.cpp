#include "helper_messages.hpp"

namespace exv::helper {

// ---- HelperMode / HelperOp conversions ----

namespace {

uint32_t mode_to_uint(HelperMode m) {
    return static_cast<uint32_t>(m);
}

HelperMode uint_to_mode(uint32_t v) {
    return static_cast<HelperMode>(v);
}

uint32_t op_to_uint(HelperOp o) {
    return static_cast<uint32_t>(o);
}

HelperOp uint_to_op(uint32_t v) {
    return static_cast<HelperOp>(v);
}

} // anonymous namespace

// ---- SessionId / ProfileId ----

void to_json(json& j, const SessionId& id) {
    j = id.value;
}

void from_json(const json& j, SessionId& id) {
    id.value = j.get<std::string>();
}

void to_json(json& j, const ProfileId& id) {
    j = id.value;
}

void from_json(const json& j, ProfileId& id) {
    id.value = j.get<std::string>();
}

// ---- HelloRequest / HelloResponse ----

void to_json(json& j, const HelloRequest& req) {
    (void)req;
    j = json::object();
}

HelloRequest hello_request_from_json(const json& j) {
    (void)j;
    return {};
}

void to_json(json& j, const HelperStartupContext& ctx) {
    j = json{{"launch_mode", ctx.launch_mode},
             {"endpoint", ctx.endpoint},
             {"owner", ctx.owner},
             {"parent_pid", ctx.parent_pid}};
}

HelperStartupContext helper_startup_context_from_json(const json& j) {
    HelperStartupContext ctx;
    ctx.launch_mode = j.value("launch_mode", "");
    ctx.endpoint = j.value("endpoint", "");
    ctx.owner = j.value("owner", "");
    ctx.parent_pid = j.value("parent_pid", 0);
    return ctx;
}

void to_json(json& j, const HelperSessionState& state) {
    j = json{{"active", state.active},
             {"session_id", state.session_id},
             {"core_phase", state.core_phase}};
}

HelperSessionState helper_session_state_from_json(const json& j) {
    HelperSessionState state;
    state.active = j.value("active", false);
    if (j.contains("session_id")) from_json(j["session_id"], state.session_id);
    state.core_phase = j.value("core_phase", "");
    return state;
}

void to_json(json& j, const CoreLeaseState& state) {
    j = json{{"active", state.active},
             {"lease_id", state.lease_id},
             {"core_pid", state.core_pid},
             {"purpose", state.purpose},
             {"last_seen_state", state.last_seen_state}};
}

void from_json(const json& j, CoreLeaseState& state) {
    state = core_lease_state_from_json(j);
}

CoreLeaseState core_lease_state_from_json(const json& j) {
    CoreLeaseState state;
    state.active = j.value("active", false);
    state.lease_id = j.value("lease_id", "");
    state.core_pid = j.value("core_pid", 0);
    state.purpose = j.value("purpose", "");
    state.last_seen_state = j.value("last_seen_state", "");
    return state;
}

void to_json(json& j, const TaskQueueState& state) {
    j = json{{"idle", state.idle},
             {"current_job_id", state.current_job_id},
             {"pending_jobs", state.pending_jobs}};
}

void from_json(const json& j, TaskQueueState& state) {
    state = task_queue_state_from_json(j);
}

TaskQueueState task_queue_state_from_json(const json& j) {
    TaskQueueState state;
    state.idle = j.value("idle", true);
    state.current_job_id = j.value("current_job_id", "");
    state.pending_jobs = j.value("pending_jobs", 0);
    return state;
}

void to_json(json& j, const HelloResponse& resp) {
    j = json{{"capabilities", resp.capabilities},
             {"mode", mode_to_uint(resp.mode)},
             {"startup_context", resp.startup_context},
             {"session_state", resp.session_state},
             {"core_lease", resp.core_lease},
             {"task_queue", resp.task_queue}};
}

HelloResponse hello_response_from_json(const json& j) {
    HelloResponse resp;
    if (j.contains("capabilities"))
        resp.capabilities = j["capabilities"].get<std::vector<std::string>>();
    if (j.contains("mode"))
        resp.mode = uint_to_mode(j["mode"].get<uint32_t>());
    if (j.contains("startup_context"))
        resp.startup_context = helper_startup_context_from_json(j["startup_context"]);
    if (j.contains("session_state"))
        resp.session_state = helper_session_state_from_json(j["session_state"]);
    if (j.contains("core_lease"))
        resp.core_lease = core_lease_state_from_json(j["core_lease"]);
    if (j.contains("task_queue"))
        resp.task_queue = task_queue_state_from_json(j["task_queue"]);
    return resp;
}

// ---- StartSessionRequest / StartSessionResponse ----

void to_json(json& j, const StartSessionRequest& req) {
    j = json{{"profile_id", req.profile_id}, {"mode", mode_to_uint(req.mode)}};
}

StartSessionRequest start_session_request_from_json(const json& j) {
    StartSessionRequest req;
    if (j.contains("profile_id")) from_json(j["profile_id"], req.profile_id);
    if (j.contains("mode")) req.mode = uint_to_mode(j["mode"].get<uint32_t>());
    return req;
}

void to_json(json& j, const StartSessionResponse& resp) {
    j = json{{"session_id", resp.session_id}};
}

StartSessionResponse start_session_response_from_json(const json& j) {
    StartSessionResponse resp;
    if (j.contains("session_id")) from_json(j["session_id"], resp.session_id);
    return resp;
}

// ---- PrepareTunnelDeviceRequest / PrepareTunnelDeviceResponse ----

void to_json(json& j, const PrepareTunnelDeviceRequest& req) {
    j = json{{"session_id", req.session_id}, {"adapter_name", req.adapter_name}};
}

PrepareTunnelDeviceRequest prepare_tunnel_device_request_from_json(const json& j) {
    PrepareTunnelDeviceRequest req;
    if (j.contains("session_id")) from_json(j["session_id"], req.session_id);
    req.adapter_name = j.value("adapter_name", "");
    return req;
}

void to_json(json& j, const PrepareTunnelDeviceResponse& resp) {
    j = json{{"device_path", resp.device_path},
             {"mtu", resp.mtu},
             {"error_code", resp.error_code},
             {"error_message", resp.error_message}};
}

PrepareTunnelDeviceResponse prepare_tunnel_device_response_from_json(const json& j) {
    PrepareTunnelDeviceResponse resp;
    resp.device_path = j.value("device_path", "");
    resp.mtu = j.value("mtu", 1400);
    resp.error_code = j.value("error_code", "");
    resp.error_message = j.value("error_message", "");
    return resp;
}

// ---- RouteEntry ----

void to_json(json& j, const RouteEntry& r) {
    j = json{{"destination", r.destination},
             {"gateway", r.gateway},
             {"metric", r.metric}};
}

RouteEntry route_entry_from_json(const json& j) {
    RouteEntry r;
    r.destination = j.value("destination", "");
    r.gateway = j.value("gateway", "");
    r.metric = j.value("metric", 0);
    return r;
}

// ---- DnsConfig ----

void to_json(json& j, const DnsConfig& d) {
    j = json{{"servers", d.servers},
             {"search_domain", d.search_domain},
             {"suffixes", d.suffixes}};
}

DnsConfig dns_config_from_json(const json& j) {
    DnsConfig d;
    if (j.contains("servers")) d.servers = j["servers"].get<std::vector<std::string>>();
    d.search_domain = j.value("search_domain", "");
    if (j.contains("suffixes")) d.suffixes = j["suffixes"].get<std::vector<std::string>>();
    return d;
}

// ---- TunnelConfig ----

void to_json(json& j, const TunnelConfig& cfg) {
    json routes = json::array();
    for (const auto& r : cfg.routes) routes.push_back(r);
    j = json{{"session_id", cfg.session_id},
             {"interface_address", cfg.interface_address},
             {"routes", routes},
             {"server_bypass_ips", cfg.server_bypass_ips},
             {"dns", cfg.dns},
             {"enable_kill_switch", cfg.enable_kill_switch}};
}

TunnelConfig tunnel_config_from_json(const json& j) {
    TunnelConfig cfg;
    if (j.contains("session_id")) from_json(j["session_id"], cfg.session_id);
    cfg.interface_address = j.value("interface_address", "");
    if (j.contains("routes")) {
        for (const auto& rj : j["routes"])
            cfg.routes.push_back(route_entry_from_json(rj));
    }
    if (j.contains("server_bypass_ips"))
        cfg.server_bypass_ips = j["server_bypass_ips"].get<std::vector<std::string>>();
    if (j.contains("dns")) cfg.dns = dns_config_from_json(j["dns"]);
    cfg.enable_kill_switch = j.value("enable_kill_switch", false);
    return cfg;
}

// ---- ApplyTunnelConfigRequest / ApplyTunnelConfigResponse ----

void to_json(json& j, const ApplyTunnelConfigRequest& req) {
    j = json{{"config", req.config}};
}

ApplyTunnelConfigRequest apply_tunnel_config_request_from_json(const json& j) {
    ApplyTunnelConfigRequest req;
    if (j.contains("config")) req.config = tunnel_config_from_json(j["config"]);
    return req;
}

void to_json(json& j, const ApplyTunnelConfigResponse& resp) {
    j = json{{"success", resp.success},
             {"error_code", resp.error_code},
             {"error_message", resp.error_message},
             {"error_target", resp.error_target},
             {"system_error", resp.system_error}};
}

ApplyTunnelConfigResponse apply_tunnel_config_response_from_json(const json& j) {
    ApplyTunnelConfigResponse resp;
    resp.success = j.value("success", false);
    resp.error_code = j.value("error_code", "");
    resp.error_message = j.value("error_message", "");
    resp.error_target = j.value("error_target", "");
    resp.system_error = j.value("system_error", 0U);
    return resp;
}

// ---- HeartbeatRequest / HeartbeatResponse ----

void to_json(json& j, const HeartbeatRequest& req) {
    j = json{{"session_id", req.session_id}, {"core_phase", req.core_phase}};
}

HeartbeatRequest heartbeat_request_from_json(const json& j) {
    HeartbeatRequest req;
    if (j.contains("session_id")) from_json(j["session_id"], req.session_id);
    req.core_phase = j.value("core_phase", "");
    return req;
}

void to_json(json& j, const HeartbeatResponse& resp) {
    j = json{{"ok", resp.ok}};
    if (resp.warning.has_value()) j["warning"] = resp.warning.value();
}

HeartbeatResponse heartbeat_response_from_json(const json& j) {
    HeartbeatResponse resp;
    resp.ok = j.value("ok", true);
    if (j.contains("warning")) resp.warning = j["warning"].get<std::string>();
    return resp;
}

// ---- CleanupPolicy ----

void to_json(json& j, const CleanupPolicy& p) {
    j = json{{"remove_routes", p.remove_routes},
             {"remove_dns", p.remove_dns},
             {"remove_adapter", p.remove_adapter},
             {"remove_firewall_rules", p.remove_firewall_rules}};
}

CleanupPolicy cleanup_policy_from_json(const json& j) {
    CleanupPolicy p;
    p.remove_routes = j.value("remove_routes", true);
    p.remove_dns = j.value("remove_dns", true);
    p.remove_adapter = j.value("remove_adapter", false);
    p.remove_firewall_rules = j.value("remove_firewall_rules", true);
    return p;
}

// ---- CleanupRequest / CleanupResponse ----

void to_json(json& j, const CleanupRequest& req) {
    j = json{{"session_id", req.session_id}, {"policy", req.policy}};
}

CleanupRequest cleanup_request_from_json(const json& j) {
    CleanupRequest req;
    if (j.contains("session_id")) from_json(j["session_id"], req.session_id);
    if (j.contains("policy")) req.policy = cleanup_policy_from_json(j["policy"]);
    return req;
}

void to_json(json& j, const CleanupResponse& resp) {
    j = json{{"success", resp.success}, {"errors", resp.errors}};
}

CleanupResponse cleanup_response_from_json(const json& j) {
    CleanupResponse resp;
    resp.success = j.value("success", false);
    if (j.contains("errors")) resp.errors = j["errors"].get<std::vector<std::string>>();
    return resp;
}

// ---- GetSnapshotRequest / SessionSnapshot / GetSnapshotResponse ----

void to_json(json& /*j*/, const GetSnapshotRequest& /*req*/) {
    // No fields
}

GetSnapshotRequest get_snapshot_request_from_json(const json& /*j*/) {
    return {};
}

void to_json(json& j, const SessionSnapshot& snap) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        snap.last_heartbeat.time_since_epoch())
        .count();
    j = json{{"session_id", snap.session_id},
             {"core_phase", snap.core_phase},
             {"last_heartbeat_ms", ms},
             {"managed_resources", snap.managed_resources}};
}

SessionSnapshot session_snapshot_from_json(const json& j) {
    SessionSnapshot snap;
    if (j.contains("session_id")) from_json(j["session_id"], snap.session_id);
    snap.core_phase = j.value("core_phase", "");
    if (j.contains("last_heartbeat_ms")) {
        auto ms = j["last_heartbeat_ms"].get<int64_t>();
        snap.last_heartbeat = std::chrono::steady_clock::time_point(
            std::chrono::milliseconds(ms));
    }
    if (j.contains("managed_resources"))
        snap.managed_resources = j["managed_resources"].get<std::vector<std::string>>();
    return snap;
}

void to_json(json& j, const GetSnapshotResponse& resp) {
    json arr = json::array();
    for (const auto& s : resp.sessions) arr.push_back(s);
    j = json{{"sessions", arr}};
}

GetSnapshotResponse get_snapshot_response_from_json(const json& j) {
    GetSnapshotResponse resp;
    if (j.contains("sessions")) {
        for (const auto& sj : j["sessions"])
            resp.sessions.push_back(session_snapshot_from_json(sj));
    }
    return resp;
}

// ---- ShutdownRequest / ShutdownResponse ----

void to_json(json& j, const ShutdownRequest& req) {
    j = json{{"session_id", req.session_id}, {"policy", req.policy}};
}

ShutdownRequest shutdown_request_from_json(const json& j) {
    ShutdownRequest req;
    if (j.contains("session_id")) from_json(j["session_id"], req.session_id);
    if (j.contains("policy")) req.policy = cleanup_policy_from_json(j["policy"]);
    return req;
}

void to_json(json& j, const ShutdownResponse& resp) {
    j = json{{"cleanup_success", resp.cleanup_success},
             {"exiting", resp.exiting},
             {"errors", resp.errors}};
}

ShutdownResponse shutdown_response_from_json(const json& j) {
    ShutdownResponse resp;
    resp.cleanup_success = j.value("cleanup_success", false);
    resp.exiting = j.value("exiting", false);
    if (j.contains("errors")) resp.errors = j["errors"].get<std::vector<std::string>>();
    return resp;
}

// ---- Inspect / Core lease control ----

void to_json(json& j, const InspectRequest& req) {
    (void)req;
    j = json::object();
}

void from_json(const json& j, InspectRequest& req) {
    req = inspect_request_from_json(j);
}

InspectRequest inspect_request_from_json(const json& j) {
    (void)j;
    return {};
}

void to_json(json& j, const InspectResponse& resp) {
    j = json{{"capabilities", resp.capabilities},
             {"mode", mode_to_uint(resp.mode)},
             {"startup_context", resp.startup_context},
             {"session_state", resp.session_state},
             {"core_lease", resp.core_lease},
             {"task_queue", resp.task_queue}};
}

void from_json(const json& j, InspectResponse& resp) {
    resp = inspect_response_from_json(j);
}

InspectResponse inspect_response_from_json(const json& j) {
    InspectResponse resp;
    if (j.contains("capabilities"))
        resp.capabilities = j["capabilities"].get<std::vector<std::string>>();
    if (j.contains("mode"))
        resp.mode = uint_to_mode(j["mode"].get<uint32_t>());
    if (j.contains("startup_context"))
        resp.startup_context = helper_startup_context_from_json(j["startup_context"]);
    if (j.contains("session_state"))
        resp.session_state = helper_session_state_from_json(j["session_state"]);
    if (j.contains("core_lease"))
        resp.core_lease = core_lease_state_from_json(j["core_lease"]);
    if (j.contains("task_queue"))
        resp.task_queue = task_queue_state_from_json(j["task_queue"]);
    return resp;
}

void to_json(json& j, const AcquireCoreLeaseRequest& req) {
    j = json{{"core_pid", req.core_pid}, {"purpose", req.purpose}};
}

void from_json(const json& j, AcquireCoreLeaseRequest& req) {
    req = acquire_core_lease_request_from_json(j);
}

AcquireCoreLeaseRequest acquire_core_lease_request_from_json(const json& j) {
    AcquireCoreLeaseRequest req;
    req.core_pid = j.value("core_pid", 0);
    req.purpose = j.value("purpose", "");
    return req;
}

void to_json(json& j, const AcquireCoreLeaseResponse& resp) {
    j = json{{"accepted", resp.accepted},
             {"lease_id", resp.lease_id},
             {"mode", resp.mode}};
}

void from_json(const json& j, AcquireCoreLeaseResponse& resp) {
    resp = acquire_core_lease_response_from_json(j);
}

AcquireCoreLeaseResponse acquire_core_lease_response_from_json(const json& j) {
    AcquireCoreLeaseResponse resp;
    resp.accepted = j.value("accepted", false);
    resp.lease_id = j.value("lease_id", "");
    resp.mode = j.value("mode", "");
    return resp;
}

void to_json(json& j, const KeepAliveRequest& req) {
    j = json{{"lease_id", req.lease_id}, {"state", req.state}};
}

void from_json(const json& j, KeepAliveRequest& req) {
    req = keep_alive_request_from_json(j);
}

KeepAliveRequest keep_alive_request_from_json(const json& j) {
    KeepAliveRequest req;
    req.lease_id = j.value("lease_id", "");
    req.state = j.value("state", "");
    return req;
}

void to_json(json& j, const KeepAliveResponse& resp) {
    j = json{{"ok", resp.ok}};
    if (resp.warning.has_value()) j["warning"] = resp.warning.value();
}

void from_json(const json& j, KeepAliveResponse& resp) {
    resp = keep_alive_response_from_json(j);
}

KeepAliveResponse keep_alive_response_from_json(const json& j) {
    KeepAliveResponse resp;
    resp.ok = j.value("ok", true);
    if (j.contains("warning")) resp.warning = j["warning"].get<std::string>();
    return resp;
}

void to_json(json& j, const ReleaseCoreLeaseRequest& req) {
    j = json{{"lease_id", req.lease_id},
             {"exit_if_oneshot", req.exit_if_oneshot}};
}

void from_json(const json& j, ReleaseCoreLeaseRequest& req) {
    req = release_core_lease_request_from_json(j);
}

ReleaseCoreLeaseRequest release_core_lease_request_from_json(const json& j) {
    ReleaseCoreLeaseRequest req;
    req.lease_id = j.value("lease_id", "");
    req.exit_if_oneshot = j.value("exit_if_oneshot", true);
    return req;
}

void to_json(json& j, const ReleaseCoreLeaseResponse& resp) {
    j = json{{"released", resp.released}, {"exiting", resp.exiting}};
}

void from_json(const json& j, ReleaseCoreLeaseResponse& resp) {
    resp = release_core_lease_response_from_json(j);
}

ReleaseCoreLeaseResponse release_core_lease_response_from_json(const json& j) {
    ReleaseCoreLeaseResponse resp;
    resp.released = j.value("released", false);
    resp.exiting = j.value("exiting", false);
    return resp;
}

void to_json(json& j, const ManagedResource& resource) {
    j = json{{"type", resource.type}, {"detail", resource.detail}};
}

void from_json(const json& j, ManagedResource& resource) {
    resource = managed_resource_from_json(j);
}

ManagedResource managed_resource_from_json(const json& j) {
    ManagedResource resource;
    resource.type = j.value("type", "");
    resource.detail = j.value("detail", "");
    return resource;
}
// ---- HelperRequest / HelperResponse (unified envelope) ----

void to_json(json& j, const HelperRequest& req) {
    j = json{{"op", op_to_uint(req.op)}, {"payload_json", req.payload_json}};
}

HelperRequest helper_request_from_json(const json& j) {
    HelperRequest req;
    if (j.contains("op")) req.op = uint_to_op(j["op"].get<uint32_t>());
    req.payload_json = j.value("payload_json", "");
    return req;
}

void to_json(json& j, const HelperResponse& resp) {
    j = json{{"op", op_to_uint(resp.op)},
             {"success", resp.success},
             {"error_code", resp.error_code},
             {"error_message", resp.error_message},
             {"payload_json", resp.payload_json}};
}

HelperResponse helper_response_from_json(const json& j) {
    HelperResponse resp;
    if (j.contains("op")) resp.op = uint_to_op(j["op"].get<uint32_t>());
    resp.success = j.value("success", false);
    resp.error_code = j.value("error_code", "");
    resp.error_message = j.value("error_message", "");
    resp.payload_json = j.value("payload_json", "");
    return resp;
}

} // namespace exv::helper
