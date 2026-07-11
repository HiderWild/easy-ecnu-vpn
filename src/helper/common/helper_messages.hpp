#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <chrono>
#include <nlohmann/json.hpp>
#include "helper_protocol.hpp"

namespace exv::helper {

using json = nlohmann::json;

struct SessionId {
    std::string value;
};

inline bool operator==(const SessionId& a, const SessionId& b) {
    return a.value == b.value;
}

inline bool operator<(const SessionId& a, const SessionId& b) {
    return a.value < b.value;
}

struct ProfileId {
    std::string value;
};

struct HelloRequest {};

struct HelperStartupContext {
    std::string launch_mode;
    std::string endpoint;
    std::string owner;
    int parent_pid = 0;
};

struct HelperSessionState {
    bool active = false;
    SessionId session_id;
    std::string core_phase;
};

struct CoreLeaseState {
    bool active = false;
    std::string lease_id;
    int core_pid = 0;
    std::string purpose;
    std::string last_seen_state;
};

struct TaskQueueState {
    bool idle = true;
    std::string current_job_id;
    int pending_jobs = 0;
};

struct HelloResponse {
    std::vector<std::string> capabilities;
    HelperMode mode = HelperMode::Transient;
    HelperStartupContext startup_context;
    HelperSessionState session_state;
    CoreLeaseState core_lease;
    TaskQueueState task_queue;
};

struct StartSessionRequest {
    ProfileId profile_id;
    HelperMode mode = HelperMode::Transient;
};

struct StartSessionResponse {
    SessionId session_id;
};

struct PrepareTunnelDeviceRequest {
    SessionId session_id;
    std::string adapter_name;  // Platform-specific
    // No credentials - helper only creates device
};

struct PrepareTunnelDeviceResponse {
    std::string device_path;   // e.g. \\.\Wintun\... or /dev/tunN
    int mtu = 1400;
    std::string error_code;
    std::string error_message;
};

struct RouteEntry {
    std::string destination;   // e.g. "0.0.0.0/0"
    std::string gateway;
    int metric = 0;
};

struct DnsConfig {
    std::vector<std::string> servers;
    std::string search_domain;
    std::vector<std::string> suffixes;
};

struct TunnelConfig {
    SessionId session_id;
    std::string interface_address;  // e.g. "10.0.0.2/24"
    std::vector<RouteEntry> routes;
    std::vector<std::string> server_bypass_ips;
    DnsConfig dns;
    bool enable_kill_switch = false;
};

struct ApplyTunnelConfigRequest {
    TunnelConfig config;
};

struct ApplyTunnelConfigResponse {
    bool success = false;
    std::string error_code;
    std::string error_message;
    std::string error_target;
    std::uint32_t system_error = 0;
};

struct HeartbeatRequest {
    SessionId session_id;
    std::string core_phase;  // Connected|Reconnecting|etc.
};

struct HeartbeatResponse {
    bool ok = true;
    std::optional<std::string> warning;
};

struct CleanupPolicy {
    bool remove_routes = true;
    bool remove_dns = true;
    bool remove_adapter = false;  // Keep adapter for reconnect
    bool remove_firewall_rules = true;
};

struct CleanupRequest {
    SessionId session_id;
    CleanupPolicy policy;
};

struct CleanupResponse {
    bool success = false;
    std::vector<std::string> errors;  // Per-resource errors
};

struct GetSnapshotRequest {};

struct SessionSnapshot {
    SessionId session_id;
    std::string core_phase;
    std::chrono::steady_clock::time_point last_heartbeat;
    std::vector<std::string> managed_resources;
};

struct GetSnapshotResponse {
    std::vector<SessionSnapshot> sessions;
};

struct ShutdownRequest {
    SessionId session_id;
    CleanupPolicy policy;
};

struct ShutdownResponse {
    bool cleanup_success = false;
    bool exiting = false;
    std::vector<std::string> errors;
};

struct InspectRequest {};

struct InspectResponse {
    std::vector<std::string> capabilities;
    HelperMode mode = HelperMode::Transient;
    HelperStartupContext startup_context;
    HelperSessionState session_state;
    CoreLeaseState core_lease;
    TaskQueueState task_queue;
};

struct AcquireCoreLeaseRequest {
    int core_pid = 0;
    std::string purpose;
};

struct AcquireCoreLeaseResponse {
    bool accepted = false;
    std::string lease_id;
    std::string mode;
    std::string error_code;
    std::string error_message;
};

struct KeepAliveRequest {
    std::string lease_id;
    std::string state;
};

struct KeepAliveResponse {
    bool ok = true;
    std::optional<std::string> warning;
};

struct ReleaseCoreLeaseRequest {
    std::string lease_id;
    bool exit_if_oneshot = true;
};

struct ReleaseCoreLeaseResponse {
    bool released = false;
    bool exiting = false;
};

struct ManagedResource {
    std::string type;
    std::string detail;
};

// --- Unified Request/Response ---

struct HelperRequest {
    HelperOp op;
    // Union of all request types (use variant in implementation)
    std::string payload_json;  // Serialized for now
};

struct HelperResponse {
    HelperOp op;
    bool success = false;
    std::string error_code;
    std::string error_message;
    std::string payload_json;  // Serialized for now
};

// --- Serialization (ADL-compatible to_json/from_json) ---

// SessionId / ProfileId
void to_json(json& j, const SessionId& id);
void from_json(const json& j, SessionId& id);
void to_json(json& j, const ProfileId& id);
void from_json(const json& j, ProfileId& id);

// Hello
void to_json(json& j, const HelloRequest& req);
HelloRequest hello_request_from_json(const json& j);
void to_json(json& j, const HelperStartupContext& ctx);
HelperStartupContext helper_startup_context_from_json(const json& j);
void to_json(json& j, const HelperSessionState& state);
HelperSessionState helper_session_state_from_json(const json& j);
void to_json(json& j, const CoreLeaseState& state);
void from_json(const json& j, CoreLeaseState& state);
CoreLeaseState core_lease_state_from_json(const json& j);
void to_json(json& j, const TaskQueueState& state);
void from_json(const json& j, TaskQueueState& state);
TaskQueueState task_queue_state_from_json(const json& j);
void to_json(json& j, const HelloResponse& resp);
HelloResponse hello_response_from_json(const json& j);

// StartSession
void to_json(json& j, const StartSessionRequest& req);
StartSessionRequest start_session_request_from_json(const json& j);
void to_json(json& j, const StartSessionResponse& resp);
StartSessionResponse start_session_response_from_json(const json& j);

// PrepareTunnelDevice
void to_json(json& j, const PrepareTunnelDeviceRequest& req);
PrepareTunnelDeviceRequest prepare_tunnel_device_request_from_json(const json& j);
void to_json(json& j, const PrepareTunnelDeviceResponse& resp);
PrepareTunnelDeviceResponse prepare_tunnel_device_response_from_json(const json& j);

// RouteEntry / DnsConfig / TunnelConfig
void to_json(json& j, const RouteEntry& r);
RouteEntry route_entry_from_json(const json& j);
void to_json(json& j, const DnsConfig& d);
DnsConfig dns_config_from_json(const json& j);
void to_json(json& j, const TunnelConfig& cfg);
TunnelConfig tunnel_config_from_json(const json& j);

// ApplyTunnelConfig
void to_json(json& j, const ApplyTunnelConfigRequest& req);
ApplyTunnelConfigRequest apply_tunnel_config_request_from_json(const json& j);
void to_json(json& j, const ApplyTunnelConfigResponse& resp);
ApplyTunnelConfigResponse apply_tunnel_config_response_from_json(const json& j);

// Heartbeat
void to_json(json& j, const HeartbeatRequest& req);
HeartbeatRequest heartbeat_request_from_json(const json& j);
void to_json(json& j, const HeartbeatResponse& resp);
HeartbeatResponse heartbeat_response_from_json(const json& j);

// Cleanup
void to_json(json& j, const CleanupPolicy& p);
CleanupPolicy cleanup_policy_from_json(const json& j);
void to_json(json& j, const CleanupRequest& req);
CleanupRequest cleanup_request_from_json(const json& j);
void to_json(json& j, const CleanupResponse& resp);
CleanupResponse cleanup_response_from_json(const json& j);

// Snapshot
void to_json(json& j, const GetSnapshotRequest& req);
GetSnapshotRequest get_snapshot_request_from_json(const json& j);
void to_json(json& j, const SessionSnapshot& snap);
SessionSnapshot session_snapshot_from_json(const json& j);
void to_json(json& j, const GetSnapshotResponse& resp);
GetSnapshotResponse get_snapshot_response_from_json(const json& j);

// Shutdown
void to_json(json& j, const ShutdownRequest& req);
ShutdownRequest shutdown_request_from_json(const json& j);
void to_json(json& j, const ShutdownResponse& resp);
ShutdownResponse shutdown_response_from_json(const json& j);

// Inspect / Core lease control
void to_json(json& j, const InspectRequest& req);
void from_json(const json& j, InspectRequest& req);
InspectRequest inspect_request_from_json(const json& j);
void to_json(json& j, const InspectResponse& resp);
void from_json(const json& j, InspectResponse& resp);
InspectResponse inspect_response_from_json(const json& j);
void to_json(json& j, const AcquireCoreLeaseRequest& req);
void from_json(const json& j, AcquireCoreLeaseRequest& req);
AcquireCoreLeaseRequest acquire_core_lease_request_from_json(const json& j);
void to_json(json& j, const AcquireCoreLeaseResponse& resp);
void from_json(const json& j, AcquireCoreLeaseResponse& resp);
AcquireCoreLeaseResponse acquire_core_lease_response_from_json(const json& j);
void to_json(json& j, const KeepAliveRequest& req);
void from_json(const json& j, KeepAliveRequest& req);
KeepAliveRequest keep_alive_request_from_json(const json& j);
void to_json(json& j, const KeepAliveResponse& resp);
void from_json(const json& j, KeepAliveResponse& resp);
KeepAliveResponse keep_alive_response_from_json(const json& j);
void to_json(json& j, const ReleaseCoreLeaseRequest& req);
void from_json(const json& j, ReleaseCoreLeaseRequest& req);
ReleaseCoreLeaseRequest release_core_lease_request_from_json(const json& j);
void to_json(json& j, const ReleaseCoreLeaseResponse& resp);
void from_json(const json& j, ReleaseCoreLeaseResponse& resp);
ReleaseCoreLeaseResponse release_core_lease_response_from_json(const json& j);
void to_json(json& j, const ManagedResource& resource);
void from_json(const json& j, ManagedResource& resource);
ManagedResource managed_resource_from_json(const json& j);

// Unified envelope
void to_json(json& j, const HelperRequest& req);
HelperRequest helper_request_from_json(const json& j);
void to_json(json& j, const HelperResponse& resp);
HelperResponse helper_response_from_json(const json& j);

} // namespace exv::helper
