// Generated from contracts/system.contract.json. Do not edit manually.

export const CONTRACT_VERSION = "2026-06-16.cli-core-ui-contract.v1" as const
export const IPC_PROTOCOL_MAJOR = 1 as const

export const DESKTOP_RPC_REQUEST_FIELDS = [
  "id",
  "action",
  "payload"
] as const
export const DESKTOP_RPC_RESPONSE_FIELDS = [
  "ok",
  "data",
  "code",
  "message",
  "event"
] as const
export const CORE_RPC_REQUEST_FIELDS = [
  "action",
  "payload_json",
  "request_id"
] as const
export const CORE_RPC_RESPONSE_FIELDS = [
  "success",
  "payload_json",
  "error_code",
  "error_message",
  "request_id"
] as const

export const CORE_RPC_ACTIONS = [
  "core.hello",
  "status.get",
  "vpn.connect",
  "vpn.disconnect",
  "config.get",
  "config.save",
  "config.getAuth",
  "config.saveAuth",
  "config.getSettings",
  "config.saveSettings",
  "config.reset",
  "config.import",
  "config.export",
  "config.get_profile",
  "config.save_profile",
  "key.status",
  "key.reset",
  "routes.list",
  "routes.add",
  "routes.remove",
  "routes.reset",
  "logs.list",
  "logs.clear",
  "service.status",
  "service.install",
  "service.uninstall",
  "service.repair",
  "runtime.status",
  "drivers.status",
  "drivers.install",
  "maintenance.inspectCore",
  "maintenance.killStaleCore"
] as const
export const DESTRUCTIVE_CORE_RPC_ACTIONS = [
  "config.reset",
  "key.reset",
  "maintenance.killStaleCore"
] as const
export const STANDARD_ERROR_CODES = [
  "confirmation_required",
  "invalid_payload",
  "invalid_config",
  "unsupported_contract_version",
  "core_comm_broken",
  "core_unresponsive",
  "core_protocol_mismatch",
  "core_not_found",
  "core_launch_failed",
  "core_version_probe_failed",
  "config_import_format_unsupported",
  "config_import_auth_failed",
  "config_import_tampered_or_wrong_password",
  "credential_store_unavailable",
  "key_missing",
  "key_corrupt",
  "log_clear_failed"
] as const

export const DESKTOP_RPC_ACTIONS = [
  "status.get",
  "vpn.connect",
  "vpn.disconnect",
  "vpn.authInteraction.get",
  "vpn.authInteraction.respond",
  "config.getAuth",
  "config.saveAuth",
  "config.getSettings",
  "config.saveSettings",
  "config.getKey",
  "routes.list",
  "routes.add",
  "routes.remove",
  "routes.reset",
  "service.status",
  "helper.status",
  "runtime.status",
  "cli.status",
  "cli.install",
  "cli.uninstall",
  "drivers.status",
  "drivers.install",
  "service.install",
  "service.uninstall",
  "service.repair",
  "logs.list",
  "logs.clear"
] as const
export const DESKTOP_RPC_EVENT_TYPES = [
  "log",
  "status",
  "heartbeat",
  "service-progress",
  "close-request",
  "core-crashed",
  "quick-start-request"
] as const
export const DESKTOP_RPC_ERROR_CODES = [
  "helper_unavailable",
  "service_not_installed",
  "service_installed_not_running",
  "service_start_failed",
  "oneshot_not_supported",
  "oneshot_elevation_denied",
  "helper_rpc_failed",
  "auth_failed",
  "auth_protocol_mismatch",
  "auth_rejected",
  "auth_challenge_required",
  "auth_group_required",
  "auth_expired",
  "csd_required_unsupported",
  "dtls_unavailable",
  "tunnel_disconnected",
  "session_timeout",
  "idle_timeout",
  "rekey_unsupported",
  "cstp_compressed_unsupported",
  "unsupported_extra_args",
  "tls_verify_failed",
  "wintun_missing",
  "utun_permission_denied",
  "unsupported_dtls",
  "permission_denied",
  "network_unreachable",
  "user_cancelled",
  "invalid_request",
  "log_clear_failed",
  "connection_failed",
  "vpn_start_failed",
  "elevation_denied",
  "launch_failed",
  "helper_not_found",
  "needs_elevation",
  "vpn_disconnect_timeout"
] as const
export const DESKTOP_RPC_ERROR_CODE_MAP = {
  "helperUnavailable": "helper_unavailable",
  "serviceNotInstalled": "service_not_installed",
  "serviceInstalledNotRunning": "service_installed_not_running",
  "serviceStartFailed": "service_start_failed",
  "oneshotNotSupported": "oneshot_not_supported",
  "oneshotElevationDenied": "oneshot_elevation_denied",
  "helperRpcFailed": "helper_rpc_failed",
  "authFailed": "auth_failed",
  "authProtocolMismatch": "auth_protocol_mismatch",
  "authRejected": "auth_rejected",
  "authChallengeRequired": "auth_challenge_required",
  "authGroupRequired": "auth_group_required",
  "authExpired": "auth_expired",
  "csdRequiredUnsupported": "csd_required_unsupported",
  "dtlsUnavailable": "dtls_unavailable",
  "tunnelDisconnected": "tunnel_disconnected",
  "sessionTimeout": "session_timeout",
  "idleTimeout": "idle_timeout",
  "rekeyUnsupported": "rekey_unsupported",
  "cstpCompressedUnsupported": "cstp_compressed_unsupported",
  "unsupportedExtraArgs": "unsupported_extra_args",
  "tlsVerifyFailed": "tls_verify_failed",
  "wintunMissing": "wintun_missing",
  "utunPermissionDenied": "utun_permission_denied",
  "unsupportedDtls": "unsupported_dtls",
  "permissionDenied": "permission_denied",
  "networkUnreachable": "network_unreachable",
  "userCancelled": "user_cancelled",
  "invalidRequest": "invalid_request",
  "logClearFailed": "log_clear_failed",
  "connectionFailed": "connection_failed",
  "vpnStartFailed": "vpn_start_failed",
  "elevationDenied": "elevation_denied",
  "launchFailed": "launch_failed",
  "helperNotFound": "helper_not_found",
  "needsElevation": "needs_elevation",
  "vpnDisconnectTimeout": "vpn_disconnect_timeout"
} as const

export const CONFIG_ACTIONS = [
  "config.getAuth",
  "config.saveAuth",
  "config.getSettings",
  "config.saveSettings",
  "config.profile.get",
  "config.profile.save"
] as const
export const CONFIG_ALIASES = {
  "config.get": "config.getSettings",
  "config.save": "config.saveSettings",
  "config.get_profile": "config.profile.get",
  "config.save_profile": "config.profile.save"
} as const
export const ACTION_OWNERS = [
  {
    "name": "core.hello",
    "owner": "core_rpc"
  },
  {
    "name": "status.get",
    "owner": "core_rpc"
  },
  {
    "name": "vpn.connect",
    "owner": "core_rpc"
  },
  {
    "name": "vpn.disconnect",
    "owner": "core_rpc"
  },
  {
    "name": "vpn.status",
    "owner": "core_rpc"
  },
  {
    "name": "vpn.set_auto_reconnect",
    "owner": "core_rpc"
  },
  {
    "name": "vpn.authInteraction.get",
    "owner": "desktop_host_adapter"
  },
  {
    "name": "vpn.authInteraction.respond",
    "owner": "desktop_host_adapter"
  },
  {
    "name": "config.get",
    "owner": "compat_alias",
    "canonical": "config.getSettings"
  },
  {
    "name": "config.save",
    "owner": "compat_alias",
    "canonical": "config.saveSettings"
  },
  {
    "name": "config.getAuth",
    "owner": "core_rpc"
  },
  {
    "name": "config.saveAuth",
    "owner": "core_rpc"
  },
  {
    "name": "config.getSettings",
    "owner": "core_rpc"
  },
  {
    "name": "config.saveSettings",
    "owner": "core_rpc"
  },
  {
    "name": "config.getKey",
    "owner": "compat_alias",
    "canonical": "key.status"
  },
  {
    "name": "config.reset",
    "owner": "core_rpc"
  },
  {
    "name": "config.import",
    "owner": "core_rpc"
  },
  {
    "name": "config.export",
    "owner": "core_rpc"
  },
  {
    "name": "config.get_profile",
    "owner": "compat_alias",
    "canonical": "config.profile.get"
  },
  {
    "name": "config.save_profile",
    "owner": "compat_alias",
    "canonical": "config.profile.save"
  },
  {
    "name": "config.profile.get",
    "owner": "core_rpc"
  },
  {
    "name": "config.profile.save",
    "owner": "core_rpc"
  },
  {
    "name": "key.status",
    "owner": "core_rpc"
  },
  {
    "name": "key.reset",
    "owner": "core_rpc"
  },
  {
    "name": "routes.list",
    "owner": "core_rpc"
  },
  {
    "name": "routes.add",
    "owner": "core_rpc"
  },
  {
    "name": "routes.remove",
    "owner": "core_rpc"
  },
  {
    "name": "routes.reset",
    "owner": "core_rpc"
  },
  {
    "name": "route.list",
    "owner": "core_rpc"
  },
  {
    "name": "route.add",
    "owner": "core_rpc"
  },
  {
    "name": "route.remove",
    "owner": "core_rpc"
  },
  {
    "name": "route.enable",
    "owner": "core_rpc"
  },
  {
    "name": "route.disable",
    "owner": "core_rpc"
  },
  {
    "name": "logs.list",
    "owner": "core_rpc"
  },
  {
    "name": "logs.clear",
    "owner": "core_rpc"
  },
  {
    "name": "service.status",
    "owner": "core_rpc"
  },
  {
    "name": "service.helper_status",
    "owner": "core_rpc"
  },
  {
    "name": "helper.status",
    "owner": "desktop_host_adapter"
  },
  {
    "name": "service.install",
    "owner": "core_rpc"
  },
  {
    "name": "service.uninstall",
    "owner": "core_rpc"
  },
  {
    "name": "service.repair",
    "owner": "core_rpc"
  },
  {
    "name": "service.driver_status",
    "owner": "core_rpc"
  },
  {
    "name": "runtime.status",
    "owner": "core_rpc"
  },
  {
    "name": "cli.status",
    "owner": "desktop_host_adapter"
  },
  {
    "name": "cli.install",
    "owner": "desktop_host_adapter"
  },
  {
    "name": "cli.uninstall",
    "owner": "desktop_host_adapter"
  },
  {
    "name": "drivers.status",
    "owner": "core_rpc"
  },
  {
    "name": "drivers.install",
    "owner": "core_rpc"
  },
  {
    "name": "maintenance.inspectCore",
    "owner": "core_rpc"
  },
  {
    "name": "maintenance.killStaleCore",
    "owner": "core_rpc"
  }
] as const
export const ACTION_OWNER_MAP = {
  "core.hello": "core_rpc",
  "status.get": "core_rpc",
  "vpn.connect": "core_rpc",
  "vpn.disconnect": "core_rpc",
  "vpn.status": "core_rpc",
  "vpn.set_auto_reconnect": "core_rpc",
  "vpn.authInteraction.get": "desktop_host_adapter",
  "vpn.authInteraction.respond": "desktop_host_adapter",
  "config.get": "compat_alias",
  "config.save": "compat_alias",
  "config.getAuth": "core_rpc",
  "config.saveAuth": "core_rpc",
  "config.getSettings": "core_rpc",
  "config.saveSettings": "core_rpc",
  "config.getKey": "compat_alias",
  "config.reset": "core_rpc",
  "config.import": "core_rpc",
  "config.export": "core_rpc",
  "config.get_profile": "compat_alias",
  "config.save_profile": "compat_alias",
  "config.profile.get": "core_rpc",
  "config.profile.save": "core_rpc",
  "key.status": "core_rpc",
  "key.reset": "core_rpc",
  "routes.list": "core_rpc",
  "routes.add": "core_rpc",
  "routes.remove": "core_rpc",
  "routes.reset": "core_rpc",
  "route.list": "core_rpc",
  "route.add": "core_rpc",
  "route.remove": "core_rpc",
  "route.enable": "core_rpc",
  "route.disable": "core_rpc",
  "logs.list": "core_rpc",
  "logs.clear": "core_rpc",
  "service.status": "core_rpc",
  "service.helper_status": "core_rpc",
  "helper.status": "desktop_host_adapter",
  "service.install": "core_rpc",
  "service.uninstall": "core_rpc",
  "service.repair": "core_rpc",
  "service.driver_status": "core_rpc",
  "runtime.status": "core_rpc",
  "cli.status": "desktop_host_adapter",
  "cli.install": "desktop_host_adapter",
  "cli.uninstall": "desktop_host_adapter",
  "drivers.status": "core_rpc",
  "drivers.install": "core_rpc",
  "maintenance.inspectCore": "core_rpc",
  "maintenance.killStaleCore": "core_rpc"
} as const
export const COMPAT_ACTION_ALIASES = {
  "config.get": "config.getSettings",
  "config.save": "config.saveSettings",
  "config.getKey": "key.status",
  "config.get_profile": "config.profile.get",
  "config.save_profile": "config.profile.save"
} as const

export const HELPER_OPS = [
  "Hello",
  "StartSession",
  "PrepareTunnelDevice",
  "ApplyTunnelConfig",
  "Heartbeat",
  "Cleanup",
  "GetSnapshot",
  "Shutdown",
  "Inspect",
  "AcquireCoreLease",
  "KeepAlive",
  "ReleaseCoreLease"
] as const
export const HELPER_OP_CONTRACTS = [
  {
    "name": "Hello",
    "code": 1,
    "request": "HelloRequest",
    "response": "HelloResponse",
    "requires_session": false
  },
  {
    "name": "StartSession",
    "code": 2,
    "request": "StartSessionRequest",
    "response": "StartSessionResponse",
    "requires_session": false
  },
  {
    "name": "PrepareTunnelDevice",
    "code": 3,
    "request": "PrepareTunnelDeviceRequest",
    "response": "PrepareTunnelDeviceResponse",
    "requires_session": true
  },
  {
    "name": "ApplyTunnelConfig",
    "code": 4,
    "request": "ApplyTunnelConfigRequest",
    "response": "ApplyTunnelConfigResponse",
    "requires_session": true
  },
  {
    "name": "Heartbeat",
    "code": 5,
    "request": "HeartbeatRequest",
    "response": "HeartbeatResponse",
    "requires_session": true
  },
  {
    "name": "Cleanup",
    "code": 6,
    "request": "CleanupRequest",
    "response": "CleanupResponse",
    "requires_session": true
  },
  {
    "name": "GetSnapshot",
    "code": 7,
    "request": "GetSnapshotRequest",
    "response": "GetSnapshotResponse",
    "requires_session": false
  },
  {
    "name": "Shutdown",
    "code": 8,
    "request": "ShutdownRequest",
    "response": "ShutdownResponse",
    "requires_session": true
  },
  {
    "name": "Inspect",
    "code": 9,
    "request": "InspectRequest",
    "response": "InspectResponse",
    "requires_session": false
  },
  {
    "name": "AcquireCoreLease",
    "code": 10,
    "request": "AcquireCoreLeaseRequest",
    "response": "AcquireCoreLeaseResponse",
    "requires_session": false
  },
  {
    "name": "KeepAlive",
    "code": 11,
    "request": "KeepAliveRequest",
    "response": "KeepAliveResponse",
    "requires_session": false
  },
  {
    "name": "ReleaseCoreLease",
    "code": 12,
    "request": "ReleaseCoreLeaseRequest",
    "response": "ReleaseCoreLeaseResponse",
    "requires_session": false
  }
] as const
export const HELPER_FORBIDDEN_CREDENTIAL_FIELDS = [
  "password",
  "passwd",
  "cookie",
  "token",
  "secret",
  "credential",
  "auth_key",
  "auth_token",
  "session_cookie",
  "webvpn_cookie",
  "csrf_token",
  "bearer_token",
  "api_key",
  "apikey"
] as const

export const TUNNEL_PHASE_CONTRACTS = [
  {
    "name": "Idle",
    "wire_name": "idle",
    "running": false,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "PreparingHelper",
    "wire_name": "preparing_helper",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "Authenticating",
    "wire_name": "authenticating",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "ConnectingCstp",
    "wire_name": "connecting_cstp",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "ApplyingNetworkConfig",
    "wire_name": "applying_network_config",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "OpeningPacketDevice",
    "wire_name": "opening_packet_device",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "Connected",
    "wire_name": "connected",
    "running": true,
    "connected": true,
    "network_ready": true
  },
  {
    "name": "Reconnecting",
    "wire_name": "reconnecting",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "Disconnecting",
    "wire_name": "disconnecting",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "CleaningUp",
    "wire_name": "cleaning_up",
    "running": true,
    "connected": false,
    "network_ready": false
  },
  {
    "name": "Failed",
    "wire_name": "failed",
    "running": false,
    "connected": false,
    "network_ready": false
  }
] as const
export const TUNNEL_EVENTS = [
  "UserConnect",
  "UserDisconnect",
  "SetAutoReconnect",
  "HelperReady",
  "AuthSucceeded",
  "AuthFailed",
  "AuthChallengeRequired",
  "AuthGroupRequired",
  "CstpConnected",
  "NetworkConfigApplied",
  "PacketLoopStarted",
  "TransportClosed",
  "PacketDeviceFailed",
  "HelperLost",
  "LeaseExpired",
  "ReconnectTimerFired",
  "CleanupSucceeded",
  "CleanupFailed"
] as const
export const TUNNEL_DISCONNECT_REASONS = [
  "UserRequested",
  "AuthFailed",
  "CertError",
  "TransportClosed",
  "HelperLost",
  "PacketDeviceFailed",
  "NetworkConfigFailed",
  "LeaseExpired"
] as const
export const TUNNEL_ERROR_DOMAINS = [
  "transport",
  "auth",
  "helper",
  "os.route",
  "os.dns",
  "packet",
  "config",
  "native"
] as const
export const TUNNEL_STATUS_FIELDS = [
  "phase",
  "desired_connected",
  "auto_reconnect",
  "helper_mode",
  "helper_status",
  "network_ready",
  "server",
  "interface_name",
  "last_error",
  "reconnect"
] as const
export const SRC_ALLOWED_TOP_LEVEL_DIRS = [
  "app",
  "base",
  "cli",
  "common",
  "contracts",
  "core",
  "feedback",
  "generated",
  "helper",
  "observability",
  "platform",
  "runtime",
  "utils",
  "vpn_engine"
] as const
export const SRC_FORBIDDEN_PATTERNS = [
  "src/*.hpp",
  "src/*.cpp",
  "src/core_api",
  "*.inc.cpp",
  "#include \"*.inc.cpp\"",
  "src/webui_assets.hpp",
  "platform include logger.hpp",
  "platform include vpn.hpp",
  "platform include tunnel.hpp",
  "platform include virtual_network.hpp",
  "platform include core/*"
] as const

export type DesktopRpcAction = (typeof DESKTOP_RPC_ACTIONS)[number]
export type CoreRpcAction = (typeof CORE_RPC_ACTIONS)[number]
export type DestructiveCoreRpcAction = (typeof DESTRUCTIVE_CORE_RPC_ACTIONS)[number]
export type ConfigAction = (typeof CONFIG_ACTIONS)[number]
export type ActionOwner = (typeof ACTION_OWNERS)[number]['owner']
export type HelperOp = (typeof HELPER_OPS)[number]
export type StandardErrorCode = (typeof STANDARD_ERROR_CODES)[number]
export type TunnelPhase = (typeof TUNNEL_PHASE_CONTRACTS)[number]['name']
export type TunnelEvent = (typeof TUNNEL_EVENTS)[number]
