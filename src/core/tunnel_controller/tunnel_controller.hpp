#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "tunnel_intent.hpp"
#include "tunnel_state.hpp"
#include "tunnel_events.hpp"
#include "reconnect_policy.hpp"

// Forward declarations — the real interfaces live in helper / platform.
namespace exv::helper { class HelperClient; }
namespace exv::platform { class PlatformNetworkOps; }
namespace exv { struct Config; }
namespace exv::vpn_engine {
struct NativeHandshakeResult;
struct VpnEngineConfig;
}

namespace exv::core {

class TunnelControllerTestAccess;

struct TunnelRecoveryRequest {
    std::uint64_t runtime_epoch = 0;
    std::uint64_t controller_id = 0;
    std::string reason;
    ErrorInfo error;
};

class TunnelController {
public:
    struct PendingAuthInteraction {
        std::string id;
        std::string kind;
        std::string label;
        std::string input_type;
        std::vector<std::string> options;
    };

    TunnelController(
        std::shared_ptr<exv::helper::HelperClient> helper,
        std::shared_ptr<exv::platform::PlatformNetworkOps> net_ops,
        ReconnectConfig reconnect_config = {}
    );
    ~TunnelController();

    /// Provide the VPN config and plaintext password used by the native
    /// engine.  Must be called before connect() when using the real engine.
    void set_vpn_config(const exv::Config& cfg,
                        const std::string& plaintext_password);
    void set_prepared_native_handshake(
        exv::vpn_engine::VpnEngineConfig engine_config,
        exv::vpn_engine::NativeHandshakeResult handshake);
    void set_runtime_identity(std::uint64_t runtime_epoch,
                              std::uint64_t controller_id);

    // User intent interface
    void connect(UserIntent intent);
    void disconnect(DisconnectReason reason = DisconnectReason::UserRequested);
    void set_auto_reconnect(bool enabled);
    std::shared_ptr<exv::helper::HelperClient> helper_client_for_maintenance() const;

    // Status
    TunnelStatusSnapshot status() const;
    TunnelPhase phase() const;
    std::optional<PendingAuthInteraction> pending_auth_interaction() const;
    bool provide_auth_interaction_response(const std::string& id,
                                           const std::string& value);

    // Event processing (called by engine/platform callbacks)
    void on_event(TunnelEvent event);

    // Recovery requests are reported to the use-case coordinator. The
    // controller must not start a second global connect workflow by itself.
    using RecoveryCallback = std::function<void(const TunnelRecoveryRequest&)>;
    void set_recovery_callback(RecoveryCallback cb);

    // Status change callback
    using StatusCallback = std::function<void(const TunnelStatusSnapshot&)>;
    void set_status_callback(StatusCallback cb);

private:
    friend class TunnelControllerTestAccess;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace exv::core
