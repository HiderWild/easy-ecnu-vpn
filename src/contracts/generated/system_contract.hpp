// Generated from contracts/system.contract.json. Do not edit manually.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace exv::contracts::generated {

inline constexpr std::string_view CONTRACT_VERSION = "2026-06-16.cli-core-ui-contract.v1";
inline constexpr std::uint32_t IPC_PROTOCOL_MAJOR = 1;

inline constexpr std::array<std::string_view, 3> DESKTOP_RPC_REQUEST_FIELDS = {{"id", "action", "payload"}};
inline constexpr std::array<std::string_view, 5> DESKTOP_RPC_RESPONSE_FIELDS = {{"ok", "data", "code", "message", "event"}};
inline constexpr std::array<std::string_view, 3> CORE_RPC_REQUEST_FIELDS = {{"action", "payload_json", "request_id"}};
inline constexpr std::array<std::string_view, 5> CORE_RPC_RESPONSE_FIELDS = {{"success", "payload_json", "error_code", "error_message", "request_id"}};

inline constexpr std::array<std::string_view, 32> CORE_RPC_ACTIONS = {{"core.hello", "status.get", "vpn.connect", "vpn.disconnect", "config.get", "config.save", "config.getAuth", "config.saveAuth", "config.getSettings", "config.saveSettings", "config.reset", "config.import", "config.export", "config.get_profile", "config.save_profile", "key.status", "key.reset", "routes.list", "routes.add", "routes.remove", "routes.reset", "logs.list", "logs.clear", "service.status", "service.install", "service.uninstall", "service.repair", "runtime.status", "drivers.status", "drivers.install", "maintenance.inspectCore", "maintenance.killStaleCore"}};
inline constexpr std::array<std::string_view, 3> DESTRUCTIVE_CORE_RPC_ACTIONS = {{"config.reset", "key.reset", "maintenance.killStaleCore"}};
inline constexpr std::array<std::string_view, 17> STANDARD_ERROR_CODES = {{"confirmation_required", "invalid_payload", "invalid_config", "unsupported_contract_version", "core_comm_broken", "core_unresponsive", "core_protocol_mismatch", "core_not_found", "core_launch_failed", "core_version_probe_failed", "config_import_format_unsupported", "config_import_auth_failed", "config_import_tampered_or_wrong_password", "credential_store_unavailable", "key_missing", "key_corrupt", "log_clear_failed"}};
inline constexpr std::array<std::string_view, 27> DESKTOP_RPC_ACTIONS = {{"status.get", "vpn.connect", "vpn.disconnect", "vpn.authInteraction.get", "vpn.authInteraction.respond", "config.getAuth", "config.saveAuth", "config.getSettings", "config.saveSettings", "config.getKey", "routes.list", "routes.add", "routes.remove", "routes.reset", "service.status", "helper.status", "runtime.status", "cli.status", "cli.install", "cli.uninstall", "drivers.status", "drivers.install", "service.install", "service.uninstall", "service.repair", "logs.list", "logs.clear"}};
inline constexpr std::array<std::string_view, 7> DESKTOP_RPC_EVENT_TYPES = {{"log", "status", "heartbeat", "service-progress", "close-request", "core-crashed", "quick-start-request"}};
inline constexpr std::array<std::string_view, 37> DESKTOP_RPC_ERROR_CODES = {{"helper_unavailable", "service_not_installed", "service_installed_not_running", "service_start_failed", "oneshot_not_supported", "oneshot_elevation_denied", "helper_rpc_failed", "auth_failed", "auth_protocol_mismatch", "auth_rejected", "auth_challenge_required", "auth_group_required", "auth_expired", "csd_required_unsupported", "dtls_unavailable", "tunnel_disconnected", "session_timeout", "idle_timeout", "rekey_unsupported", "cstp_compressed_unsupported", "unsupported_extra_args", "tls_verify_failed", "wintun_missing", "utun_permission_denied", "unsupported_dtls", "permission_denied", "network_unreachable", "user_cancelled", "invalid_request", "log_clear_failed", "connection_failed", "vpn_start_failed", "elevation_denied", "launch_failed", "helper_not_found", "needs_elevation", "vpn_disconnect_timeout"}};
inline constexpr std::array<std::string_view, 6> CONFIG_ACTIONS = {{"config.getAuth", "config.saveAuth", "config.getSettings", "config.saveSettings", "config.profile.get", "config.profile.save"}};
inline constexpr std::array<std::string_view, 4> CONFIG_LEGACY_ALIASES = {{"config.get", "config.save", "config.get_profile", "config.save_profile"}};
inline constexpr std::array<std::string_view, 12> HELPER_OPS = {{"Hello", "StartSession", "PrepareTunnelDevice", "ApplyTunnelConfig", "Heartbeat", "Cleanup", "GetSnapshot", "Shutdown", "Inspect", "AcquireCoreLease", "KeepAlive", "ReleaseCoreLease"}};
inline constexpr std::array<std::string_view, 11> TUNNEL_PHASES = {{"Idle", "PreparingHelper", "Authenticating", "ConnectingCstp", "ApplyingNetworkConfig", "OpeningPacketDevice", "Connected", "Reconnecting", "Disconnecting", "CleaningUp", "Failed"}};
inline constexpr std::array<std::string_view, 18> TUNNEL_EVENTS = {{"UserConnect", "UserDisconnect", "SetAutoReconnect", "HelperReady", "AuthSucceeded", "AuthFailed", "AuthChallengeRequired", "AuthGroupRequired", "CstpConnected", "NetworkConfigApplied", "PacketLoopStarted", "TransportClosed", "PacketDeviceFailed", "HelperLost", "LeaseExpired", "ReconnectTimerFired", "CleanupSucceeded", "CleanupFailed"}};
inline constexpr std::array<std::string_view, 8> TUNNEL_DISCONNECT_REASONS = {{"UserRequested", "AuthFailed", "CertError", "TransportClosed", "HelperLost", "PacketDeviceFailed", "NetworkConfigFailed", "LeaseExpired"}};
inline constexpr std::array<std::string_view, 8> TUNNEL_ERROR_DOMAINS = {{"transport", "auth", "helper", "os.route", "os.dns", "packet", "config", "native"}};
inline constexpr std::array<std::string_view, 10> TUNNEL_STATUS_FIELDS = {{"phase", "desired_connected", "auto_reconnect", "helper_mode", "helper_status", "network_ready", "server", "interface_name", "last_error", "reconnect"}};
inline constexpr std::array<std::string_view, 14> SRC_ALLOWED_TOP_LEVEL_DIRS = {{"app", "base", "cli", "common", "contracts", "core", "feedback", "generated", "helper", "observability", "platform", "runtime", "utils", "vpn_engine"}};
inline constexpr std::array<std::string_view, 11> SRC_FORBIDDEN_PATTERNS = {{"src/*.hpp", "src/*.cpp", "src/core_api", "*.inc.cpp", "#include \"*.inc.cpp\"", "src/webui_assets.hpp", "platform include logger.hpp", "platform include vpn.hpp", "platform include tunnel.hpp", "platform include virtual_network.hpp", "platform include core/*"}};
inline constexpr std::array<std::string_view, 14> HELPER_FORBIDDEN_CREDENTIAL_FIELDS = {{"password", "passwd", "cookie", "token", "secret", "credential", "auth_key", "auth_token", "session_cookie", "webvpn_cookie", "csrf_token", "bearer_token", "api_key", "apikey"}};

struct ActionOwnerContract {
    std::string_view name;
    std::string_view owner;
    std::string_view canonical;
};

inline constexpr std::array<ActionOwnerContract, 50> ACTION_OWNERS = {{
    {"core.hello", "core_rpc", ""},
    {"status.get", "core_rpc", ""},
    {"vpn.connect", "core_rpc", ""},
    {"vpn.disconnect", "core_rpc", ""},
    {"vpn.status", "core_rpc", ""},
    {"vpn.set_auto_reconnect", "core_rpc", ""},
    {"vpn.authInteraction.get", "desktop_host_adapter", ""},
    {"vpn.authInteraction.respond", "desktop_host_adapter", ""},
    {"config.get", "compat_alias", "config.getSettings"},
    {"config.save", "compat_alias", "config.saveSettings"},
    {"config.getAuth", "core_rpc", ""},
    {"config.saveAuth", "core_rpc", ""},
    {"config.getSettings", "core_rpc", ""},
    {"config.saveSettings", "core_rpc", ""},
    {"config.getKey", "compat_alias", "key.status"},
    {"config.reset", "core_rpc", ""},
    {"config.import", "core_rpc", ""},
    {"config.export", "core_rpc", ""},
    {"config.get_profile", "compat_alias", "config.profile.get"},
    {"config.save_profile", "compat_alias", "config.profile.save"},
    {"config.profile.get", "core_rpc", ""},
    {"config.profile.save", "core_rpc", ""},
    {"key.status", "core_rpc", ""},
    {"key.reset", "core_rpc", ""},
    {"routes.list", "core_rpc", ""},
    {"routes.add", "core_rpc", ""},
    {"routes.remove", "core_rpc", ""},
    {"routes.reset", "core_rpc", ""},
    {"route.list", "core_rpc", ""},
    {"route.add", "core_rpc", ""},
    {"route.remove", "core_rpc", ""},
    {"route.enable", "core_rpc", ""},
    {"route.disable", "core_rpc", ""},
    {"logs.list", "core_rpc", ""},
    {"logs.clear", "core_rpc", ""},
    {"service.status", "core_rpc", ""},
    {"service.helper_status", "core_rpc", ""},
    {"helper.status", "desktop_host_adapter", ""},
    {"service.install", "core_rpc", ""},
    {"service.uninstall", "core_rpc", ""},
    {"service.repair", "core_rpc", ""},
    {"service.driver_status", "core_rpc", ""},
    {"runtime.status", "core_rpc", ""},
    {"cli.status", "desktop_host_adapter", ""},
    {"cli.install", "desktop_host_adapter", ""},
    {"cli.uninstall", "desktop_host_adapter", ""},
    {"drivers.status", "core_rpc", ""},
    {"drivers.install", "core_rpc", ""},
    {"maintenance.inspectCore", "core_rpc", ""},
    {"maintenance.killStaleCore", "core_rpc", ""},
}};

struct HelperOpContract {
    std::string_view name;
    std::uint32_t code;
    bool requires_session;
};

inline constexpr std::array<HelperOpContract, 12> HELPER_OP_CONTRACTS = {{
    {"Hello", 1, false},
    {"StartSession", 2, false},
    {"PrepareTunnelDevice", 3, true},
    {"ApplyTunnelConfig", 4, true},
    {"Heartbeat", 5, true},
    {"Cleanup", 6, true},
    {"GetSnapshot", 7, false},
    {"Shutdown", 8, true},
    {"Inspect", 9, false},
    {"AcquireCoreLease", 10, false},
    {"KeepAlive", 11, false},
    {"ReleaseCoreLease", 12, false},
}};

struct ConfigAlias {
    std::string_view alias;
    std::string_view target;
};

inline constexpr std::array<ConfigAlias, 4> CONFIG_ALIASES = {{
    {"config.get", "config.getSettings"},
    {"config.save", "config.saveSettings"},
    {"config.get_profile", "config.profile.get"},
    {"config.save_profile", "config.profile.save"},
}};

struct TunnelPhaseContract {
    std::string_view name;
    std::string_view wire_name;
    bool running;
    bool connected;
    bool network_ready;
};

inline constexpr std::array<TunnelPhaseContract, 11> TUNNEL_PHASE_CONTRACTS = {{
    {"Idle", "idle", false, false, false},
    {"PreparingHelper", "preparing_helper", true, false, false},
    {"Authenticating", "authenticating", true, false, false},
    {"ConnectingCstp", "connecting_cstp", true, false, false},
    {"ApplyingNetworkConfig", "applying_network_config", true, false, false},
    {"OpeningPacketDevice", "opening_packet_device", true, false, false},
    {"Connected", "connected", true, true, true},
    {"Reconnecting", "reconnecting", true, false, false},
    {"Disconnecting", "disconnecting", true, false, false},
    {"CleaningUp", "cleaning_up", true, false, false},
    {"Failed", "failed", false, false, false},
}};

template <std::size_t N>
constexpr bool contains(const std::array<std::string_view, N>& values, std::string_view value) {
    for (const auto item : values) {
        if (item == value) {
            return true;
        }
    }
    return false;
}

constexpr bool is_desktop_rpc_action(std::string_view action) {
    return contains(DESKTOP_RPC_ACTIONS, action);
}

constexpr std::string_view action_owner_for(std::string_view action) {
    for (const auto item : ACTION_OWNERS) {
        if (item.name == action) {
            return item.owner;
        }
    }
    return {};
}

constexpr bool action_has_owner(std::string_view action, std::string_view owner) {
    return action_owner_for(action) == owner;
}

constexpr bool is_core_owned_action(std::string_view action) {
    return action_has_owner(action, "core_rpc");
}

constexpr bool is_desktop_host_adapter_action(std::string_view action) {
    return action_has_owner(action, "desktop_host_adapter");
}

constexpr bool is_compat_alias(std::string_view action) {
    return action_has_owner(action, "compat_alias");
}

constexpr std::string_view canonical_action_for(std::string_view action) {
    for (const auto item : ACTION_OWNERS) {
        if (item.name == action) {
            return item.canonical.empty() ? item.name : item.canonical;
        }
    }
    return {};
}

constexpr bool is_core_rpc_action(std::string_view action) {
    return contains(CORE_RPC_ACTIONS, action);
}

constexpr bool is_destructive_core_rpc_action(std::string_view action) {
    return contains(DESTRUCTIVE_CORE_RPC_ACTIONS, action);
}

constexpr bool is_standard_error_code(std::string_view code) {
    return contains(STANDARD_ERROR_CODES, code);
}

constexpr bool is_config_action(std::string_view action) {
    return contains(CONFIG_ACTIONS, action);
}

constexpr bool is_config_alias(std::string_view alias) {
    return contains(CONFIG_LEGACY_ALIASES, alias);
}

constexpr bool is_helper_op(std::string_view op) {
    return contains(HELPER_OPS, op);
}

constexpr bool is_tunnel_phase(std::string_view phase) {
    return contains(TUNNEL_PHASES, phase);
}

constexpr bool is_tunnel_event(std::string_view event) {
    return contains(TUNNEL_EVENTS, event);
}

constexpr bool is_tunnel_disconnect_reason(std::string_view reason) {
    return contains(TUNNEL_DISCONNECT_REASONS, reason);
}

constexpr bool is_tunnel_error_domain(std::string_view domain) {
    return contains(TUNNEL_ERROR_DOMAINS, domain);
}

constexpr bool is_helper_forbidden_credential_field(std::string_view field) {
    return contains(HELPER_FORBIDDEN_CREDENTIAL_FIELDS, field);
}

} // namespace exv::contracts::generated
