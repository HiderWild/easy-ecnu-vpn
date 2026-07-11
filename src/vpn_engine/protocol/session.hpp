#pragma once

#include "vpn_engine/engine.hpp"
#include "vpn_engine/event_sink.hpp"
#include "vpn_engine/packet_device.hpp"
#include "vpn_engine/protocol/auth.hpp"
#include "vpn_engine/protocol/dtls_policy.hpp"
#include "vpn_engine/protocol/url.hpp"
#include "vpn_engine/session_state.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

class CancellationToken {
public:
  virtual ~CancellationToken() = default;
  virtual bool is_cancelled() const = 0;
};

struct AuthInteractionRequest {
  std::string id;
  std::string kind;
  std::string label;
  std::string input_type;
  std::vector<std::string> options;
};

struct AuthInteractionResponse {
  bool ok = false;
  std::string value;
};

struct ProtocolSessionOptions {
  ParsedVpnUrl server;
  std::string username;
  std::string password;
  std::string useragent;
  std::string auth_group;
  std::string csd_wrapper;
  bool disable_dtls = false;
  DtlsMode dtls_mode = DtlsMode::Auto;
  bool auto_reconnect = false;
  int max_reconnects = 1; // Only used when auto_reconnect=true; 0 = unlimited.
  int packet_loop_no_data_poll_limit = 1000;

  // Safe tunnel MTU applied when the gateway-negotiated MTU is missing or out
  // of the supported [576, 1500] range. Defaults to the AnyConnect-typical
  // 1290; the engine overrides it from configuration.
  int mtu_fallback = 1290;

  // Liveness servicing (DPD / keepalive). These are expressed in consecutive
  // idle outbound-poll counts (one idle poll is ~1ms). 0 disables that timer.
  // Responding to an inbound DPD request is always on and not gated by these.
  int liveness_idle_polls_per_second = 1000;
  int keepalive_idle_poll_interval = 0;
  int dpd_idle_poll_interval = 0;
  int dead_peer_poll_budget = 0;
  int rekey_idle_poll_interval = 0;
  int idle_timeout_idle_poll_limit = 0;
  int session_timeout_idle_poll_limit = 0;
  std::string rekey_method;

  // Optional synchronous continuation hook for aggregate-auth group selection
  // or challenge prompts. Production UI wiring is intentionally outside the
  // wire protocol layer; when this hook is absent, the transport returns the
  // stable *_required error instead.
  std::function<AuthInteractionResponse(const AuthInteractionRequest &)>
      auth_interaction_handler;

  // Optional test seam for lifecycle policy decisions. Production uses
  // steady_clock so cookie reuse is bounded by gateway session-timeout metadata.
  std::function<std::chrono::steady_clock::time_point()> monotonic_clock;
};

// Classification of a single CSTP frame received from the gateway. This is the
// public CSTP/AnyConnect record taxonomy used by the full-duplex data plane.
enum class InboundFrameKind {
  none,
  data,
  dpd_request,
  dpd_response,
  keepalive,
  disconnect,
  compressed,
  terminate,
};

struct InboundFrame {
  InboundFrameKind kind = InboundFrameKind::none;
  std::vector<std::uint8_t> payload;
};

// ProtocolTransport is the narrow boundary between the deterministic protocol
// session state machine and the production TLS/CSTP transport. The data plane
// is full-duplex: outbound IP packets are framed and written independently of
// inbound CSTP frames, which are read and classified independently.
class ProtocolTransport {
public:
  virtual ~ProtocolTransport() = default;

  virtual AuthResult authenticate(const ProtocolSessionOptions &options) = 0;
  virtual ValidationResult connect_cstp(const std::string &cookie,
                                        TunnelMetadata *metadata) = 0;

  // Outbound data path: frame a single IP packet as a CSTP data record and
  // write it to the stream. Must be safe to call concurrently with
  // receive_frame (which only reads from the stream).
  virtual ValidationResult
  send_packet(const std::vector<std::uint8_t> &packet) = 0;

  // Outbound control path: send a control record (e.g. dpd_response,
  // keepalive). Must be safe to call concurrently with receive_frame.
  virtual ValidationResult send_control(InboundFrameKind kind) = 0;

  // Inbound path: block until the next complete CSTP frame is available,
  // decode and classify it. Returns a transport_closed error only on underlying
  // stream EOF/interruption; peer control frames are returned as frame kinds.
  virtual ValidationResult receive_frame(InboundFrame *out) = 0;

  virtual bool can_fallback_to_cstp() const { return false; }
  virtual void fallback_to_cstp(const std::string & /*reason*/,
                                const std::string & /*code*/) {}

  virtual void disconnect() = 0;
  virtual void reset_for_reconnect() = 0;
};

class ProtocolSession {
public:
  ProtocolSession(ProtocolSessionOptions options, ProtocolTransport *transport);

  ValidationResult authenticate();
  ValidationResult connect_cstp(TunnelMetadata *metadata);
  ValidationResult run_packet_loop(PacketDevice *device, EventSink *events,
                                   CancellationToken *cancel,
                                   const DeviceConfig *device_config = nullptr);
  void disconnect();

  const SessionState &state() const;
  const AuthResult &last_auth_result() const;
  int reconnect_attempts() const;

private:
  // Outcome of a single full-duplex forwarding session (between connect and a
  // disconnect/cancel/error). Distinguishes a clean cancel/stop from a fatal
  // transport/device error that may warrant a reconnect.
  struct ForwardingOutcome {
    ValidationResult result;
    bool cancelled = false;
  };

  ValidationResult reconnect(PacketDevice *device, EventSink *events,
                             CancellationToken *cancel,
                             const DeviceConfig &device_config,
                             bool explicit_device_config);
  void apply_gateway_liveness_metadata(const TunnelMetadata &metadata);
  ForwardingOutcome run_forwarding(PacketDevice *device, EventSink *events,
                                   CancellationToken *cancel);
  ValidationResult stop_cancelled(PacketDevice *device, EventSink *events);
  bool cancellation_requested(const CancellationToken *cancel) const;
  std::chrono::steady_clock::time_point monotonic_now() const;
  bool cached_cookie_within_session_timeout() const;

  ProtocolSessionOptions options_;
  ProtocolTransport *transport_ = nullptr;
  SessionState state_;
  AuthResult last_auth_result_;
  std::string cookie_;
  TunnelMetadata metadata_;
  std::chrono::steady_clock::time_point cstp_connected_at_{};
  int cookie_session_timeout_seconds_ = 0;
  bool authenticated_ = false;
  bool cstp_connected_ = false;
  int reconnect_attempts_ = 0;
  std::atomic<bool> disconnect_requested_{false};
  PacketDevice *current_device_ = nullptr;
};

} // namespace protocol
} // namespace vpn_engine
} // namespace exv
