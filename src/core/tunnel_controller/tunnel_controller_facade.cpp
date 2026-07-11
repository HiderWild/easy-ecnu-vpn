#include "core/tunnel_controller/tunnel_controller_impl.hpp"

namespace exv::core {

// =========================================================================
// TunnelController — pimpl delegation
// =========================================================================

TunnelController::TunnelController(
    std::shared_ptr<exv::helper::HelperClient> helper,
    std::shared_ptr<exv::platform::PlatformNetworkOps> net_ops,
    ReconnectConfig reconnect_config)
    : impl_(std::make_unique<Impl>())
{
    impl_->helper_          = std::move(helper);
    impl_->net_ops_         = std::move(net_ops);
    impl_->reconnect_policy_ = ReconnectPolicy(reconnect_config);

    // Wire the CoreSessionRunner event callback to feed back into
    // TunnelController::on_event(), driving the state machine.
    impl_->runner_.set_event_callback([this](TunnelEvent event) {
        this->on_event(std::move(event));
    });
    impl_->runner_.set_network_config_callback(
        [this](const exv::vpn_engine::TunnelMetadata& metadata,
               exv::vpn_engine::DeviceConfig* device_config) {
            return impl_->configure_network_for_engine(metadata, device_config);
        });
}

TunnelController::~TunnelController() {
    if (impl_) {
        impl_->stop_heartbeat();
        impl_->stop_core_lease_keepalive();
        impl_->scheduler_.shutdown();
        impl_->runner_.stop();
        if ((impl_->network_config_applied_ ||
             !impl_->session_id_.value.empty()) &&
            impl_->helper_) {
            impl_->shutdown_helper_session_for_cleanup();
        }
        impl_->release_core_lease();
    }
}

void TunnelController::set_vpn_config(const exv::Config& cfg,
                                      const std::string& plaintext_password) {
    impl_->vpn_cfg_      = cfg;
    impl_->vpn_password_ = plaintext_password;
    impl_->prepared_native_handshake_.reset();
}

void TunnelController::set_prepared_native_handshake(
    exv::vpn_engine::VpnEngineConfig engine_config,
    exv::vpn_engine::NativeHandshakeResult handshake) {
    impl_->prepared_native_handshake_ =
        Impl::PreparedNativeHandshake{std::move(engine_config),
                                      std::move(handshake)};
}

// ------------------------------------------------------------------
// User intent interface
// ------------------------------------------------------------------

void TunnelController::connect(UserIntent intent) {
    if (!impl_->can_start_connect()) {
        return;   // reject — already connecting / connected / disconnecting
    }
    impl_->intent_ = std::move(intent);
    impl_->do_connect();
}

void TunnelController::disconnect(DisconnectReason reason) {
    if (!impl_->can_disconnect()) {
        return;   // nothing to disconnect from
    }
    impl_->do_disconnect(reason);
}

void TunnelController::set_auto_reconnect(bool enabled) {
    impl_->intent_.auto_reconnect = enabled;
    impl_->update_snapshot();
    impl_->notify_status();
}

std::shared_ptr<exv::helper::HelperClient>
TunnelController::helper_client_for_maintenance() const {
    return impl_->helper_;
}

// ------------------------------------------------------------------
// Status
// ------------------------------------------------------------------

TunnelStatusSnapshot TunnelController::status() const {
    return impl_->snapshot_;
}

TunnelPhase TunnelController::phase() const {
    return impl_->phase_;
}

std::optional<TunnelController::PendingAuthInteraction>
TunnelController::pending_auth_interaction() const {
    auto pending = impl_->runner_.pending_auth_interaction();
    if (!pending) {
        return std::nullopt;
    }
    return PendingAuthInteraction{
        pending->id,
        pending->kind,
        pending->label,
        pending->input_type,
        pending->options,
    };
}

bool TunnelController::provide_auth_interaction_response(
    const std::string& id, const std::string& value) {
    return impl_->runner_.provide_auth_interaction_response(id, value);
}

// ------------------------------------------------------------------
// Event processing
// ------------------------------------------------------------------

void TunnelController::on_event(TunnelEvent event) {
    switch (event.type) {

    // --- Connect-flow events ---
    case TunnelEventType::HelperReady:
        impl_->on_helper_ready();
        break;
    case TunnelEventType::AuthSucceeded:
        impl_->on_auth_succeeded();
        break;
    case TunnelEventType::AuthFailed:
        impl_->on_auth_failed();
        break;
    case TunnelEventType::AuthChallengeRequired:
    case TunnelEventType::AuthGroupRequired:
        // Interaction metadata is surfaced through the native engine event log;
        // the subsequent auth failure event drives the existing state change.
        break;
    case TunnelEventType::CstpConnected:
        impl_->on_cstp_connected();
        break;
    case TunnelEventType::NetworkConfigApplied:
        impl_->on_network_config_applied();
        break;
    case TunnelEventType::PacketLoopStarted:
        impl_->on_packet_loop_started();
        break;

    // --- Failure / disconnect events ---
    case TunnelEventType::TransportClosed:
        impl_->on_transport_closed();
        break;
    case TunnelEventType::PacketDeviceFailed:
        impl_->on_packet_device_failed();
        break;
    case TunnelEventType::LeaseExpired:
        impl_->on_lease_expired();
        break;

    // --- Reconnect ---
    case TunnelEventType::ReconnectTimerFired:
        impl_->on_reconnect_timer_fired();
        break;

    // --- Helper lifecycle ---
    case TunnelEventType::HelperLost:
        impl_->on_helper_lost();
        break;

    // --- Cleanup ---
    case TunnelEventType::CleanupSucceeded:
        impl_->on_cleanup_succeeded();
        break;
    case TunnelEventType::CleanupFailed:
        impl_->on_cleanup_failed();
        break;

    // --- User intent events (handled by connect/disconnect/set_auto_reconnect) ---
    case TunnelEventType::UserConnect:
    case TunnelEventType::UserDisconnect:
    case TunnelEventType::SetAutoReconnect:
        // These are dispatched through the dedicated methods, not on_event.
        break;
    }
}

// ------------------------------------------------------------------
// Callback
// ------------------------------------------------------------------

void TunnelController::set_status_callback(StatusCallback cb) {
    impl_->status_callback_ = std::move(cb);
}

} // namespace exv::core
