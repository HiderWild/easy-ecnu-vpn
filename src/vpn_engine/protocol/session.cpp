#include "vpn_engine/protocol/session.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace exv {
namespace vpn_engine {
namespace protocol {

namespace {

constexpr const char *kDtlsFallbackState = "attempted_and_fell_back_to_tls";

ValidationResult invalid(std::string code, std::string message) {
  ValidationResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

void emit_event(EventSink *events, std::string type, std::string level,
                std::string message,
                std::map<std::string, std::string> fields = {}) {
  if (!events)
    return;

  VpnEngineEvent event;
  event.type = std::move(type);
  event.level = std::move(level);
  event.message = std::move(message);
  event.fields = std::move(fields);
  events->emit(event);
}

bool is_clean_packet_loop_end(const ValidationResult &result) {
  return result.code == "packet_device_empty";
}

bool is_retryable_packet_read(const ValidationResult &result) {
  return result.code == "no_data" || result.code == "try_again" ||
         result.code == "would_block";
}

bool is_reconnect_trigger(const ValidationResult &result) {
  return result.code == "transport_closed" ||
         result.code == "rekey_unsupported";
}

bool is_dtls_data_failure(const ValidationResult &result) {
  return result.code == "udp_timeout" || result.code.rfind("dtls_", 0) == 0;
}

bool is_cached_cookie_rejected(const ValidationResult &result) {
  return result.code == "auth_expired" ||
         result.code == "auth_cookie_invalid" ||
         result.code == "auth_required";
}

ValidationResult cancelled() {
  return invalid("session_cancelled", "protocol session is cancelled");
}

DeviceConfig device_config_from_metadata(const TunnelMetadata &metadata) {
  DeviceConfig config;
  config.interface_name = metadata.interface_name;
  config.mtu = metadata.mtu;
  return config;
}

int seconds_to_idle_polls(int seconds, int polls_per_second) {
  if (seconds <= 0)
    return 0;
  if (polls_per_second <= 0)
    polls_per_second = 1000;
  if (seconds > std::numeric_limits<int>::max() / polls_per_second)
    return std::numeric_limits<int>::max();
  return seconds * polls_per_second;
}

std::string lower_ascii(const std::string &value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char ch : value)
    out.push_back(static_cast<char>(std::tolower(ch)));
  return out;
}

} // namespace

ProtocolSession::ProtocolSession(ProtocolSessionOptions options,
                                 ProtocolTransport *transport)
    : options_(std::move(options)), transport_(transport) {}

ValidationResult ProtocolSession::authenticate() {
  if (!transport_)
    return invalid("transport_missing", "protocol transport is not configured");
  if (disconnect_requested_.load())
    return invalid("session_cancelled", "protocol session is cancelled");

  state_.auth_started();

  AuthResult auth = transport_->authenticate(options_);
  last_auth_result_ = auth;
  if (last_auth_result_.ok)
    last_auth_result_.cookie.clear();
  if (!auth.ok) {
    authenticated_ = false;
    cookie_.clear();
    state_.failed(auth.error_code, auth.error_message);
    return invalid(auth.error_code, auth.error_message);
  }

  authenticated_ = true;
  cookie_ = std::move(auth.cookie);
  state_.auth_succeeded();
  return ValidationResult{};
}

ValidationResult ProtocolSession::connect_cstp(TunnelMetadata *metadata) {
  if (!metadata)
    return invalid("cstp_null_metadata", "metadata output must not be null");
  if (!transport_)
    return invalid("transport_missing", "protocol transport is not configured");
  if (disconnect_requested_.load())
    return invalid("session_cancelled", "protocol session is cancelled");
  if (!authenticated_)
    return invalid("auth_required", "authenticate must succeed before CSTP connect");

  TunnelMetadata connected_metadata;
  ValidationResult connected =
      transport_->connect_cstp(cookie_, &connected_metadata);
  if (!connected.ok) {
    cstp_connected_ = false;
    state_.failed(connected.code, connected.message);
    return connected;
  }

  // Defensive tunnel-MTU normalization at the device seam: the gateway value
  // is validated by the CSTP parser, but a misbehaving/forged transport could
  // still yield an unusable MTU. Fall back to the configured safe default
  // rather than handing an out-of-range value to the platform packet device.
  if (connected_metadata.mtu < 576 || connected_metadata.mtu > 1500) {
    int fallback = options_.mtu_fallback;
    if (fallback < 576 || fallback > 1500)
      fallback = 1290;
    connected_metadata.mtu = fallback;
  }

  metadata_ = connected_metadata;
  cstp_connected_at_ = monotonic_now();
  cookie_session_timeout_seconds_ = connected_metadata.session_timeout_seconds;
  *metadata = connected_metadata;
  cstp_connected_ = true;
  state_.tunnel_configured(connected_metadata);
  apply_gateway_liveness_metadata(connected_metadata);
  return ValidationResult{};
}

void ProtocolSession::apply_gateway_liveness_metadata(
    const TunnelMetadata &metadata) {
  const int polls_per_second = options_.liveness_idle_polls_per_second > 0
                                   ? options_.liveness_idle_polls_per_second
                                   : 1000;

  const int keepalive =
      seconds_to_idle_polls(metadata.keepalive_seconds, polls_per_second);
  if (keepalive > 0)
    options_.keepalive_idle_poll_interval = keepalive;

  const int dpd = seconds_to_idle_polls(metadata.dpd_seconds, polls_per_second);
  if (dpd > 0) {
    options_.dpd_idle_poll_interval = dpd;
    if (options_.dead_peer_poll_budget <= 0)
      options_.dead_peer_poll_budget = dpd;
  }

  const int rekey =
      seconds_to_idle_polls(metadata.rekey_seconds, polls_per_second);
  if (rekey > 0)
    options_.rekey_idle_poll_interval = rekey;
  if (!metadata.rekey_method.empty())
    options_.rekey_method = metadata.rekey_method;

  const int idle_timeout =
      seconds_to_idle_polls(metadata.idle_timeout_seconds, polls_per_second);
  if (idle_timeout > 0)
    options_.idle_timeout_idle_poll_limit = idle_timeout;

  const int session_timeout =
      seconds_to_idle_polls(metadata.session_timeout_seconds, polls_per_second);
  if (session_timeout > 0)
    options_.session_timeout_idle_poll_limit = session_timeout;
}

ValidationResult ProtocolSession::run_packet_loop(PacketDevice *device,
                                                  EventSink *events,
                                                  CancellationToken *cancel,
                                                  const DeviceConfig *device_config) {
  if (!device)
    return invalid("packet_device_missing", "packet device is not configured");
  if (!transport_)
    return invalid("transport_missing", "protocol transport is not configured");
  if (cancellation_requested(cancel)) {
    return stop_cancelled(nullptr, events);
  }
  if (!cstp_connected_)
    return invalid("cstp_not_connected",
                   "connect_cstp must succeed before packet loop");

  const DeviceConfig active_device_config =
      device_config ? *device_config : device_config_from_metadata(metadata_);

  current_device_ = device;
  ValidationResult opened = device->open(active_device_config);
  if (!opened.ok) {
    current_device_ = nullptr;
    state_.failed(opened.code, opened.message);
    emit_event(events, "packet_device.failed", "error", opened.message,
               {{"code", opened.code}});
    return opened;
  }

  state_.packet_loop_started();
  emit_event(events, "packet.loop.started", "info", "packet loop started");

  while (true) {
    ForwardingOutcome outcome = run_forwarding(device, events, cancel);

    if (outcome.cancelled) {
      return stop_cancelled(device, events);
    }

    if (outcome.result.ok) {
      // Graceful end of the forwarding session (e.g. the device drained). Close
      // the device on this (the loop) thread but leave the session marked
      // network-ready and report success.
      device->close();
      current_device_ = nullptr;
      return outcome.result;
    }

    const ValidationResult &failed = outcome.result;
    emit_event(events, "transport.closed", "error", failed.message,
               {{"code", failed.code}});

    const bool reconnect_attempts_available =
        options_.max_reconnects == 0 ||
        reconnect_attempts_ < options_.max_reconnects;
    const bool can_reconnect =
        is_reconnect_trigger(failed) && options_.auto_reconnect &&
        reconnect_attempts_available && !cancellation_requested(cancel);

    if (can_reconnect) {
      ValidationResult reconnected =
          reconnect(device, events, cancel, active_device_config,
                    device_config != nullptr);
      if (reconnected.ok)
        continue;
      current_device_ = nullptr;
      return reconnected;
    }

    device->close();
    current_device_ = nullptr;
    state_.failed(failed.code, failed.message);
    return failed;
  }
}

ProtocolSession::ForwardingOutcome
ProtocolSession::run_forwarding(PacketDevice *device, EventSink *events,
                                CancellationToken *cancel) {
  std::atomic<bool> stop{false};

  // Monotonic counter of inbound CSTP frames seen by the reader thread. Any
  // frame (data, keepalive, DPD request/response) proves the peer is alive and
  // is used by the outbound thread's dead-peer detector.
  std::atomic<std::uint64_t> inbound_activity{0};

  // terminate reason: 0 = none, 1 = graceful, 2 = cancelled, 3 = fatal.
  std::mutex reason_mu;
  int reason = 0;
  ValidationResult fatal;
  std::mutex fallback_mu;
  bool runtime_dtls_fallback_done = false;

  auto set_reason = [&](int new_reason, ValidationResult result) {
    const std::lock_guard<std::mutex> lock(reason_mu);
    if (reason == 0) {
      reason = new_reason;
      if (new_reason == 3)
        fatal = std::move(result);
    }
    stop.store(true);
  };

  auto fallback_dtls_to_cstp = [&](const ValidationResult &failed) {
    if (!is_dtls_data_failure(failed))
      return false;

    const std::string code =
        failed.code.empty() ? "dtls_runtime_failure" : failed.code;
    {
      const std::lock_guard<std::mutex> lock(fallback_mu);
      if (runtime_dtls_fallback_done)
        return true;
      if (!transport_->can_fallback_to_cstp())
        return false;
      transport_->fallback_to_cstp("dtls_runtime_failure", code);
      metadata_.active_data_channel = "cstp_tls";
      metadata_.dtls_state = kDtlsFallbackState;
      metadata_.dtls_fallback_reason = code;
      ++metadata_.dtls_fallback_count;
      state_.tunnel = metadata_;
      runtime_dtls_fallback_done = true;
    }
    emit_event(events, "dtls.fallback", "warning",
               "DTLS data channel failed; falling back to CSTP/TLS",
               {{"code", code}});
    return true;
  };

  // Inbound: drain CSTP frames from the gateway and route them to the device.
  // Runs until the transport reports a closed/failed read (which the outbound
  // side triggers via transport_->disconnect()), a peer disconnect frame, a
  // device write failure, or cancellation. It intentionally does not gate on
  // `stop` so that frames already queued when the outbound side ends are still
  // drained before the transport read reports closure.
  std::thread inbound([&]() {
    while (true) {
      if (cancellation_requested(cancel)) {
        set_reason(2, ValidationResult{});
        break;
      }

      InboundFrame frame;
      ValidationResult received = transport_->receive_frame(&frame);
      if (!received.ok) {
        if (fallback_dtls_to_cstp(received))
          continue;
        set_reason(3, received);
        break;
      }

      // Any decoded frame is liveness evidence for the dead-peer detector.
      inbound_activity.fetch_add(1, std::memory_order_relaxed);

      if (frame.kind == InboundFrameKind::data) {
        ValidationResult written = device->write_packet(frame.payload);
        if (!written.ok) {
          set_reason(3, written);
          break;
        }
        emit_event(events, "packet.inbound", "info", "inbound packet",
                   {{"bytes", std::to_string(frame.payload.size())}});
        continue;
      }

      if (frame.kind == InboundFrameKind::dpd_request) {
        // Servicing an inbound DPD request is mandatory regardless of timers:
        // answer with a DPD response so the gateway sees us as alive.
        ValidationResult responded =
            transport_->send_control(InboundFrameKind::dpd_response);
        if (!responded.ok) {
          set_reason(3, responded);
          break;
        }
        emit_event(events, "dpd.responded", "info", "DPD response sent");
        continue;
      }

      if (frame.kind == InboundFrameKind::compressed) {
        set_reason(3,
                   invalid("cstp_compressed_unsupported",
                           "CSTP compressed frame is not supported"));
        break;
      }

      if (frame.kind == InboundFrameKind::disconnect) {
        set_reason(3,
                   invalid("tunnel_disconnected",
                           "CSTP peer requested disconnect"));
        break;
      }

      if (frame.kind == InboundFrameKind::terminate) {
        set_reason(3,
                   invalid("tunnel_disconnected",
                           "CSTP peer requested tunnel termination"));
        break;
      }

      // dpd_response / keepalive / none: already counted as activity above;
      // no further data-plane action.
    }

    // Signal the outbound (loop) thread to stop. The device is non-blocking and
    // polled by the outbound thread, so it observes `stop` and exits on its own;
    // the loop thread owns closing the device.
    stop.store(true);
  });

  // Outbound: read IP packets from the device and frame them to the gateway.
  int retryable_read_count = 0;
  const int max_retryable_reads =
      options_.packet_loop_no_data_poll_limit < 0
          ? 0
          : options_.packet_loop_no_data_poll_limit;

  // Dead-peer / keepalive state for the idle path.
  bool dpd_probe_outstanding = false;
  std::uint64_t dpd_probe_baseline = 0;
  int dpd_wait_polls = 0;
  bool rekey_due = false;

  // Services keepalive/DPD timers on each idle outbound poll. Returns a non-ok
  // result to terminate forwarding (transport_closed for a dead peer, or a
  // propagated control-write failure). `idle_polls` is the current count of
  // consecutive idle polls.
  auto service_liveness = [&](int idle_polls) -> ValidationResult {
    if (options_.session_timeout_idle_poll_limit > 0 &&
        idle_polls >= options_.session_timeout_idle_poll_limit) {
      return invalid("session_timeout", "CSTP session timeout elapsed");
    }

    if (options_.idle_timeout_idle_poll_limit > 0 &&
        idle_polls >= options_.idle_timeout_idle_poll_limit) {
      return invalid("idle_timeout", "CSTP idle timeout elapsed");
    }

    if (!rekey_due && options_.rekey_idle_poll_interval > 0 &&
        idle_polls >= options_.rekey_idle_poll_interval) {
      rekey_due = true;
      const std::string method = lower_ascii(options_.rekey_method);
      emit_event(events, "rekey.due", "warning", "CSTP rekey is due",
                 {{"method", options_.rekey_method.empty()
                                  ? std::string("new-tunnel")
                                  : options_.rekey_method}});
      if (method == "ssl") {
        return invalid("rekey_unsupported",
                       "CSTP SSL rekey is unsupported; reconnect required");
      }
      return invalid("transport_closed",
                     "CSTP new-tunnel rekey requested reconnect");
    }

    // Dead-peer detection: if a DPD probe is outstanding and no inbound frame
    // has arrived since it was sent, count down the budget.
    if (dpd_probe_outstanding) {
      if (inbound_activity.load(std::memory_order_relaxed) !=
          dpd_probe_baseline) {
        dpd_probe_outstanding = false;
        dpd_wait_polls = 0;
      } else if (options_.dead_peer_poll_budget > 0) {
        ++dpd_wait_polls;
        if (dpd_wait_polls >= options_.dead_peer_poll_budget) {
          emit_event(events, "dpd.dead", "error",
                     "dead peer detected: no response to DPD probe");
          return invalid("transport_closed",
                         "dead peer detected: no response to DPD probe");
        }
      }
    }

    if (options_.keepalive_idle_poll_interval > 0 &&
        (idle_polls % options_.keepalive_idle_poll_interval) == 0) {
      ValidationResult sent = transport_->send_control(InboundFrameKind::keepalive);
      if (!sent.ok)
        return sent;
      emit_event(events, "keepalive.sent", "info", "keepalive sent");
    }

    if (options_.dpd_idle_poll_interval > 0 && !dpd_probe_outstanding &&
        (idle_polls % options_.dpd_idle_poll_interval) == 0) {
      ValidationResult sent =
          transport_->send_control(InboundFrameKind::dpd_request);
      if (!sent.ok)
        return sent;
      dpd_probe_outstanding = true;
      dpd_probe_baseline = inbound_activity.load(std::memory_order_relaxed);
      dpd_wait_polls = 0;
      emit_event(events, "dpd.request", "info", "DPD probe sent");
    }

    return {};
  };

  while (!stop.load()) {
    if (cancellation_requested(cancel)) {
      set_reason(2, ValidationResult{});
      break;
    }

    std::vector<std::uint8_t> packet;
    ValidationResult read = device->read_packet(&packet);
    if (!read.ok) {
      if (is_clean_packet_loop_end(read)) {
        set_reason(1, ValidationResult{});
        break;
      }

      if (is_retryable_packet_read(read)) {
        ++retryable_read_count;
        if (cancellation_requested(cancel)) {
          set_reason(2, ValidationResult{});
          break;
        }
        if (retryable_read_count <= max_retryable_reads && !stop.load()) {
          ValidationResult live = service_liveness(retryable_read_count);
          if (!live.ok) {
            set_reason(3, live);
            break;
          }
          std::this_thread::yield();
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
          continue;
        }
        if (stop.load())
          break;
      }

      set_reason(3, read);
      break;
    }

    retryable_read_count = 0;

    ValidationResult sent = transport_->send_packet(packet);
    if (!sent.ok) {
      if (fallback_dtls_to_cstp(sent))
        continue;
      set_reason(3, sent);
      break;
    }

    emit_event(events, "packet.outbound", "info", "outbound packet",
               {{"bytes", std::to_string(packet.size())}});
  }

  stop.store(true);
  // Unblock a blocking inbound transport read.
  transport_->disconnect();
  inbound.join();

  ForwardingOutcome outcome;
  {
    const std::lock_guard<std::mutex> lock(reason_mu);
    outcome.cancelled = reason == 2;
    if (reason == 3)
      outcome.result = fatal;
  }
  return outcome;
}

void ProtocolSession::disconnect() {
  disconnect_requested_.store(true);

  if (transport_)
    transport_->disconnect();
  if (current_device_)
    current_device_->close();

  authenticated_ = false;
  cstp_connected_ = false;
  cookie_.clear();
  state_.stopped();
}

const SessionState &ProtocolSession::state() const { return state_; }

const AuthResult &ProtocolSession::last_auth_result() const {
  return last_auth_result_;
}

int ProtocolSession::reconnect_attempts() const { return reconnect_attempts_; }

ValidationResult ProtocolSession::reconnect(PacketDevice *device,
                                            EventSink *events,
                                            CancellationToken *cancel,
                                            const DeviceConfig &device_config,
                                            bool explicit_device_config) {
  ++reconnect_attempts_;
  state_.phase = SessionPhase::reconnecting;
  emit_event(events, "reconnect_started", "info", "reconnect started",
             {{"attempt", std::to_string(reconnect_attempts_)}});

  const std::string cached_cookie = cookie_;
  const bool cached_cookie_lifecycle_valid =
      !cached_cookie.empty() && cached_cookie_within_session_timeout();

  device->close();
  transport_->disconnect();
  transport_->reset_for_reconnect();

  authenticated_ = cached_cookie_lifecycle_valid;
  cstp_connected_ = false;
  cookie_ = cached_cookie_lifecycle_valid ? cached_cookie : std::string();
  metadata_ = TunnelMetadata{};

  if (cancellation_requested(cancel)) {
    return stop_cancelled(nullptr, events);
  }

  TunnelMetadata metadata;
  bool connected_with_cached_cookie = false;
  if (!cached_cookie.empty() && !cached_cookie_lifecycle_valid) {
    emit_event(events, "reconnect.cookie_expired", "warning",
               "cached AnyConnect cookie exceeded session timeout",
               {{"code", "session_timeout"},
                {"attempt", std::to_string(reconnect_attempts_)}});
  }

  if (!cookie_.empty()) {
    ValidationResult cached_connected = connect_cstp(&metadata);
    if (cached_connected.ok) {
      connected_with_cached_cookie = true;
      emit_event(events, "reconnect.cookie_reused", "info",
                 "reconnect reused cached AnyConnect cookie",
                 {{"attempt", std::to_string(reconnect_attempts_)}});
    } else if (is_cached_cookie_rejected(cached_connected)) {
      authenticated_ = false;
      cstp_connected_ = false;
      cookie_.clear();
      metadata_ = TunnelMetadata{};
      state_.phase = SessionPhase::reconnecting;
      state_.failure_code.clear();
      state_.failure_message.clear();
      emit_event(events, "reconnect.cookie_expired", "warning",
                 "cached AnyConnect cookie was rejected",
                 {{"code", cached_connected.code},
                  {"attempt", std::to_string(reconnect_attempts_)}});
    } else {
      emit_event(events, "reconnect_failed", "error", cached_connected.message,
                 {{"code", cached_connected.code},
                  {"attempt", std::to_string(reconnect_attempts_)}});
      return cached_connected;
    }
  }

  if (!connected_with_cached_cookie) {
    ValidationResult auth = authenticate();
    if (!auth.ok) {
      emit_event(events, "reconnect_failed", "error", auth.message,
                 {{"code", auth.code},
                  {"attempt", std::to_string(reconnect_attempts_)}});
      return auth;
    }

    ValidationResult connected = connect_cstp(&metadata);
    if (!connected.ok) {
      emit_event(events, "reconnect_failed", "error", connected.message,
                 {{"code", connected.code},
                  {"attempt", std::to_string(reconnect_attempts_)}});
      return connected;
    }
  }

  if (cancellation_requested(cancel)) {
    return stop_cancelled(nullptr, events);
  }

  DeviceConfig reconnect_device_config = device_config_from_metadata(metadata_);
  if (explicit_device_config && !device_config.interface_name.empty())
    reconnect_device_config.interface_name = device_config.interface_name;
  if (reconnect_device_config.mtu <= 0)
    reconnect_device_config.mtu = device_config.mtu;

  ValidationResult opened = device->open(reconnect_device_config);
  if (!opened.ok) {
    state_.failed(opened.code, opened.message);
    emit_event(events, "packet_device.failed", "error", opened.message,
               {{"code", opened.code}});
    emit_event(events, "reconnect_failed", "error", opened.message,
               {{"code", opened.code},
                {"attempt", std::to_string(reconnect_attempts_)}});
    return opened;
  }

  state_.packet_loop_started();
  emit_event(events, "packet.loop.started", "info", "packet loop started");
  emit_event(events, "reconnect_succeeded", "info", "reconnect succeeded",
             {{"attempt", std::to_string(reconnect_attempts_)}});
  return ValidationResult{};
}

ValidationResult ProtocolSession::stop_cancelled(PacketDevice *device,
                                                 EventSink *events) {
  if (device)
    device->close();
  current_device_ = nullptr;
  state_.stopped();
  emit_event(events, "packet.loop.stopped", "info", "packet loop stopped");
  return cancelled();
}

bool ProtocolSession::cancellation_requested(
    const CancellationToken *cancel) const {
  return disconnect_requested_.load() || (cancel && cancel->is_cancelled());
}

std::chrono::steady_clock::time_point ProtocolSession::monotonic_now() const {
  if (options_.monotonic_clock)
    return options_.monotonic_clock();
  return std::chrono::steady_clock::now();
}

bool ProtocolSession::cached_cookie_within_session_timeout() const {
  if (cookie_session_timeout_seconds_ <= 0)
    return true;

  const auto timeout =
      std::chrono::seconds(cookie_session_timeout_seconds_);
  return monotonic_now() - cstp_connected_at_ < timeout;
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv
