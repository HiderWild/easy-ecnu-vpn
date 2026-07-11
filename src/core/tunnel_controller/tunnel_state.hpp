#pragma once
#include <cstdint>
#include <string>
#include <optional>
#include "connect_progress.hpp"
#include "tunnel_intent.hpp"

namespace exv::core {

enum class TunnelPhase {
    Idle,
    PreparingHelper,
    Authenticating,
    ConnectingCstp,
    ApplyingNetworkConfig,
    OpeningPacketDevice,
    Connected,
    Reconnecting,
    Disconnecting,
    CleaningUp,
    Failed
};

inline constexpr const char* tunnel_phase_wire_name(TunnelPhase phase) noexcept {
    switch (phase) {
    case TunnelPhase::Idle: return "idle";
    case TunnelPhase::PreparingHelper: return "preparing_helper";
    case TunnelPhase::Authenticating: return "authenticating";
    case TunnelPhase::ConnectingCstp: return "connecting_cstp";
    case TunnelPhase::ApplyingNetworkConfig: return "applying_network_config";
    case TunnelPhase::OpeningPacketDevice: return "opening_packet_device";
    case TunnelPhase::Connected: return "connected";
    case TunnelPhase::Reconnecting: return "reconnecting";
    case TunnelPhase::Disconnecting: return "disconnecting";
    case TunnelPhase::CleaningUp: return "cleaning_up";
    case TunnelPhase::Failed: return "failed";
    }
    return "unknown";
}

struct ErrorInfo {
    std::string domain;    // transport|auth|helper|os.route|os.dns|packet
    std::string code;      // transport_closed, auth_failed, etc.
    std::string message;
    std::optional<int> native_code;
    std::string native_api;
    bool recoverable = false;
    std::string recommended_action;
};

struct ReconnectInfo {
    int attempt = 0;
    int next_retry_ms = 0;
};

struct TunnelStatusSnapshot {
    std::uint64_t runtime_epoch = 0;
    std::uint64_t controller_id = 0;
    TunnelPhase phase = TunnelPhase::Idle;
    bool desired_connected = false;
    bool auto_reconnect = true;
    std::string helper_mode;      // transient|resident
    std::string helper_status;    // connected|unavailable|permission_denied
    std::string helper_endpoint;
    bool core_lease_active = false;
    bool session_active = false;
    bool network_ready = false;
    std::string server;
    std::string interface_name;
    std::string internal_ip;
    std::string dtls_mode = "auto";
    std::string active_data_channel = "cstp_tls";
    std::string dtls_state = "disabled";
    std::string dtls_fallback_reason;
    int dtls_fallback_count = 0;
    std::optional<ErrorInfo> last_error;
    std::optional<ReconnectInfo> reconnect;
    ConnectProgress connect_progress;
};

} // namespace exv::core
