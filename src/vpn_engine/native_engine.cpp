#include "vpn_engine/native_engine.hpp"

#include "vpn_engine/native_handshake_job.hpp"

#include <exception>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace exv {
namespace vpn_engine {

namespace {

ValidationResult invalid(std::string code, std::string message) {
  ValidationResult result;
  result.ok = false;
  result.code = std::move(code);
  result.message = std::move(message);
  return result;
}

ValidationResult native_packet_device_unimplemented() {
  return invalid("native_packet_device_unimplemented",
                 "Native engine packet device factory is not configured.");
}

DeviceConfig device_config_from_metadata(const TunnelMetadata &metadata) {
  DeviceConfig config;
  config.interface_name = metadata.interface_name;
  config.mtu = metadata.mtu;
  return config;
}

} // namespace

ValidationResult validate_native_config(const VpnEngineConfig &cfg) {
  if (cfg.server.empty())
    return invalid("config_invalid", "VPN server is not configured.");
  if (cfg.username.empty())
    return invalid("config_invalid", "VPN username is not configured.");
  if (cfg.password.empty())
    return invalid("config_invalid", "VPN password is not configured.");
  return ValidationResult{};
}

nlohmann::json event_to_json(const VpnEngineEvent &event) {
  return nlohmann::json{{"type", event.type},
                        {"level", event.level},
                        {"message", event.message},
                        {"fields", event.fields}};
}

nlohmann::json status_to_json(const VpnEngineStatus &status) {
  return nlohmann::json{{"running", status.running},
                        {"network_ready", status.network_ready},
                        {"pid", status.pid},
                        {"interface", status.interface_name},
                        {"internal_ip", status.internal_ip},
                        {"dtls_mode", status.dtls_mode},
                        {"active_data_channel", status.active_data_channel},
                        {"dtls_state", status.dtls_state},
                        {"dtls_fallback_reason",
                         status.dtls_fallback_reason},
                        {"dtls_fallback_count", status.dtls_fallback_count},
                        {"error_code", status.error_code},
                        {"error_message", status.error_message}};
}

void apply_tunnel_metadata_to_status(VpnEngineStatus *status,
                                     const TunnelMetadata &metadata) {
  if (!status)
    return;
  status->dtls_mode = metadata.dtls_mode;
  status->active_data_channel = metadata.active_data_channel;
  status->dtls_state = metadata.dtls_state;
  status->dtls_fallback_reason = metadata.dtls_fallback_reason;
  status->dtls_fallback_count = metadata.dtls_fallback_count;
}

class NativeVpnEngineSession::LoopEventSink final : public EventSink {
public:
  explicit LoopEventSink(NativeVpnEngineSession *owner) : owner_(owner) {}

  void emit(const VpnEngineEvent &event) override {
    if (owner_)
      owner_->on_loop_event(event);
    if (owner_ && owner_->dependencies_.event_sink)
      owner_->dependencies_.event_sink->emit(event);
  }

private:
  NativeVpnEngineSession *owner_ = nullptr;
};

NativeVpnEngineSession::NativeVpnEngineSession(VpnEngineConfig config)
    : NativeVpnEngineSession(std::move(config),
                             default_native_engine_dependencies()) {}

NativeVpnEngineSession::NativeVpnEngineSession(
    VpnEngineConfig config, NativeVpnEngineDependencies dependencies)
    : config_(std::move(config)), dependencies_(std::move(dependencies)) {}

NativeVpnEngineSession::~NativeVpnEngineSession() { stop(); }

ValidationResult NativeVpnEngineSession::start() {
  TunnelMetadata metadata;
  ValidationResult handshake = start_handshake(&metadata);
  if (!handshake.ok)
    return handshake;

  auto fail = [this](const ValidationResult &failure) {
    std::unique_ptr<protocol::ProtocolTransport> transport;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      set_failure_locked(failure);
      protocol_session_.reset();
      transport = std::move(transport_);
    }
    if (transport)
      transport->disconnect();
    emit_event("native.start.failed", "error", failure.message,
               {{"code", failure.code}});
    return failure;
  };

  DeviceConfig packet_device_config = device_config_from_metadata(metadata);
  if (dependencies_.network_configurator) {
    ValidationResult network =
        dependencies_.network_configurator(metadata, &packet_device_config);
    if (!network.ok)
      return fail(network);
  }

  if (packet_device_config.interface_name.empty())
    packet_device_config.interface_name = metadata.interface_name;
  if (packet_device_config.mtu <= 0)
    packet_device_config.mtu = metadata.mtu;

  return start_packet_loop(packet_device_config);
}

ValidationResult NativeVpnEngineSession::start_handshake(TunnelMetadata *metadata) {
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (status_.running || packet_loop_thread_.joinable() || transport_ ||
        protocol_session_) {
      return invalid("session_already_running",
                     "Native VPN engine session is already running.");
    }

    status_ = VpnEngineStatus{};
    loop_started_ = false;
    loop_finished_ = false;
    loop_start_result_ = ValidationResult{};
    cancel_requested_.store(false);
    handshake_metadata_ = TunnelMetadata{};
  }

  auto fail = [this](const ValidationResult &failure) {
    {
      const std::lock_guard<std::mutex> lock(mu_);
      set_failure_locked(failure);
    }
    emit_event("native.start.failed", "error", failure.message,
               {{"code", failure.code}});
    return failure;
  };

  NativeHandshakeResult handshake;
  NativeHandshakeJob job(config_, dependencies_);
  ValidationResult result = job.run(std::stop_token{}, &handshake);
  if (!result.ok)
    return fail(result);

  {
    const std::lock_guard<std::mutex> lock(mu_);
    handshake_metadata_ = handshake.metadata;
    status_.pid = -1;
    status_.interface_name = handshake_metadata_.interface_name;
    status_.internal_ip = handshake_metadata_.internal_ip4_address;
    apply_tunnel_metadata_to_status(&status_, handshake_metadata_);
    status_.error_code.clear();
    status_.error_message.clear();
    transport_ = std::move(handshake.transport);
    protocol_session_ = std::move(handshake.session);
  }

  if (metadata)
    *metadata = handshake_metadata_;

  return {};
}

ValidationResult NativeVpnEngineSession::adopt_handshake(
    NativeHandshakeResult handshake, TunnelMetadata *metadata) {
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (status_.running || packet_loop_thread_.joinable() || transport_ ||
        protocol_session_) {
      return invalid("session_already_running",
                     "Native VPN engine session is already running.");
    }
  }

  if (!handshake.transport || !handshake.session) {
    ValidationResult failure = invalid(
        "handshake_incomplete",
        "Native VPN engine handshake result is missing transport or session.");
    {
      const std::lock_guard<std::mutex> lock(mu_);
      set_failure_locked(failure);
    }
    emit_event("native.start.failed", "error", failure.message,
               {{"code", failure.code}});
    return failure;
  }

  {
    const std::lock_guard<std::mutex> lock(mu_);
    status_ = VpnEngineStatus{};
    loop_started_ = false;
    loop_finished_ = false;
    loop_start_result_ = ValidationResult{};
    cancel_requested_.store(false);
    handshake_metadata_ = handshake.metadata;
    status_.pid = -1;
    status_.interface_name = handshake_metadata_.interface_name;
    status_.internal_ip = handshake_metadata_.internal_ip4_address;
    apply_tunnel_metadata_to_status(&status_, handshake_metadata_);
    status_.error_code.clear();
    status_.error_message.clear();
    transport_ = std::move(handshake.transport);
    protocol_session_ = std::move(handshake.session);
  }

  if (metadata)
    *metadata = handshake_metadata_;

  return {};
}

ValidationResult NativeVpnEngineSession::start_packet_loop(
    DeviceConfig packet_device_config) {
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (status_.running || packet_loop_thread_.joinable()) {
      return invalid("session_already_running",
                     "Native VPN engine session is already running.");
    }
    if (!transport_ || !protocol_session_) {
      return invalid("handshake_required",
                     "Native VPN engine handshake has not completed.");
    }
  }

  auto fail = [this](const ValidationResult &failure) {
    std::unique_ptr<protocol::ProtocolTransport> transport;
    {
      const std::lock_guard<std::mutex> lock(mu_);
      set_failure_locked(failure);
      protocol_session_.reset();
      packet_device_.reset();
      loop_event_sink_.reset();
      transport = std::move(transport_);
    }
    if (transport)
      transport->disconnect();
    emit_event("native.start.failed", "error", failure.message,
               {{"code", failure.code}});
    return failure;
  };

  if (!dependencies_.packet_device_factory) {
    return fail(native_packet_device_unimplemented());
  }

  std::unique_ptr<PacketDevice> packet_device;
  try {
    packet_device = dependencies_.packet_device_factory();
  } catch (const std::exception &e) {
    return fail(invalid("native_packet_device_factory_failed", e.what()));
  } catch (...) {
    return fail(invalid("native_packet_device_factory_failed",
                        "Native packet device factory failed."));
  }

  if (!packet_device) {
    return fail(native_packet_device_unimplemented());
  }

  {
    const std::lock_guard<std::mutex> lock(mu_);
    packet_device_config_ = packet_device_config;
    packet_device_ = std::move(packet_device);
    loop_event_sink_ = std::make_unique<LoopEventSink>(this);
  }

  packet_loop_thread_ = std::thread(&NativeVpnEngineSession::run_packet_loop, this);

  std::unique_lock<std::mutex> lock(mu_);
  startup_cv_.wait(lock,
                   [this]() { return loop_started_ || loop_finished_; });

  if (loop_started_)
    return ValidationResult{};

  ValidationResult failure = loop_start_result_;
  lock.unlock();

  if (packet_loop_thread_.joinable())
    packet_loop_thread_.join();

  if (failure.ok) {
    failure = invalid("packet_loop_not_started",
                      "Native packet loop exited before startup completed.");
  }

  return fail(failure);
}

void NativeVpnEngineSession::stop() {
  cancel_requested_.store(true);

  if (packet_loop_thread_.joinable())
    packet_loop_thread_.join();

  std::unique_ptr<protocol::ProtocolSession> session;
  std::unique_ptr<protocol::ProtocolTransport> transport;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    status_.running = false;
    status_.network_ready = false;
    status_.pid = -1;
    session = std::move(protocol_session_);
    transport = std::move(transport_);
    packet_device_.reset();
    loop_event_sink_.reset();
    loop_started_ = false;
    loop_finished_ = true;
  }

  if (session) {
    session->disconnect();
  } else if (transport) {
    transport->disconnect();
  }
}

VpnEngineStatus NativeVpnEngineSession::status() const {
  const std::lock_guard<std::mutex> lock(mu_);
  return status_;
}

bool NativeVpnEngineSession::is_cancelled() const {
  return cancel_requested_.load();
}

void NativeVpnEngineSession::emit_event(
    std::string type, std::string level, std::string message,
    std::map<std::string, std::string> fields) {
  if (!dependencies_.event_sink)
    return;

  VpnEngineEvent event;
  event.type = std::move(type);
  event.level = std::move(level);
  event.message = std::move(message);
  event.fields = std::move(fields);
  dependencies_.event_sink->emit(event);
}

void NativeVpnEngineSession::on_loop_event(const VpnEngineEvent &event) {
  bool notify_startup = false;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    if (event.type == "packet.loop.started") {
      status_.running = true;
      status_.network_ready = true;
      status_.pid = -1;
      status_.error_code.clear();
      status_.error_message.clear();
      loop_started_ = true;
      loop_start_result_ = ValidationResult{};
      notify_startup = true;
    } else if (event.type == "dtls.fallback") {
      status_.active_data_channel = "cstp_tls";
      status_.dtls_state = "attempted_and_fell_back_to_tls";
      const auto code = event.fields.find("code");
      status_.dtls_fallback_reason =
          code == event.fields.end() ? "dtls_runtime_failure" : code->second;
      ++status_.dtls_fallback_count;
    } else {
      return;
    }
  }
  if (notify_startup)
    startup_cv_.notify_all();
}

void NativeVpnEngineSession::run_packet_loop() {
  ValidationResult result;

  std::unique_ptr<protocol::ProtocolTransport> transport;
  std::unique_ptr<protocol::ProtocolSession> session;
  std::unique_ptr<PacketDevice> device;
  std::unique_ptr<LoopEventSink> events;
  DeviceConfig packet_device_config;
  {
    const std::lock_guard<std::mutex> lock(mu_);
    transport = std::move(transport_);
    session = std::move(protocol_session_);
    device = std::move(packet_device_);
    events = std::move(loop_event_sink_);
    packet_device_config = packet_device_config_;
  }

  if (!session || !device) {
    result = invalid("packet_loop_missing_dependency",
                     "Native packet loop dependency is missing.");
  } else {
    result = session->run_packet_loop(device.get(), events.get(), this,
                                      &packet_device_config);
  }

  if (session) {
    session->disconnect();
  } else if (transport) {
    transport->disconnect();
  }

  if (device)
    device->close();

  {
    const std::lock_guard<std::mutex> lock(mu_);
    loop_finished_ = true;
    status_.running = false;
    status_.network_ready = false;
    status_.pid = -1;
    if (!loop_started_) {
      loop_start_result_ = result;
      if (!result.ok)
        set_failure_locked(result);
    } else if (!result.ok) {
      if (result.code != "session_cancelled")
        set_failure_locked(result);
    }
  }

  startup_cv_.notify_all();
}

void NativeVpnEngineSession::set_failure_locked(
    const ValidationResult &failure) {
  status_.running = false;
  status_.network_ready = false;
  status_.pid = -1;
  status_.error_code = failure.code;
  status_.error_message = failure.message;
}

} // namespace vpn_engine
} // namespace exv
