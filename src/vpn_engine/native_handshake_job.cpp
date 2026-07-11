#include "vpn_engine/native_handshake_job.hpp"

#include "vpn_engine/protocol/dtls_transport.hpp"
#include "vpn_engine/protocol/url.hpp"

#include <exception>
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

ValidationResult cancelled() {
  return invalid("cancelled", "Native handshake cancelled");
}

ValidationResult native_transport_unimplemented() {
  return invalid("native_transport_unimplemented",
                 "Native transport is not available on this platform.");
}

protocol::DtlsMode dtls_mode_from_config(const VpnEngineConfig &config) {
  if (config.disable_dtls || config.dtls_mode == "disabled")
    return protocol::DtlsMode::Disabled;
  if (config.dtls_mode == "enabled")
    return protocol::DtlsMode::Enabled;
  return protocol::DtlsMode::Auto;
}

std::map<std::string, std::string>
dtls_event_fields(const TunnelMetadata &metadata) {
  return {{"mode", metadata.dtls_mode},
          {"state", metadata.dtls_state},
          {"active_data_channel", metadata.active_data_channel},
          {"fallback_reason", metadata.dtls_fallback_reason},
          {"fallback_count", std::to_string(metadata.dtls_fallback_count)}};
}

bool make_auth_interaction_event(
    const ValidationResult &failure, const protocol::AuthResult &auth_result,
    std::string *type, std::map<std::string, std::string> *fields) {
  if (!type || !fields) {
    return false;
  }

  if (failure.code == "auth_challenge_required") {
    *type = "auth.challenge_required";
  } else if (failure.code == "auth_group_required") {
    *type = "auth.group_required";
  } else {
    return false;
  }

  fields->clear();
  fields->emplace("code", failure.code);
  if (!auth_result.interaction_prompt_label.empty()) {
    fields->emplace("label", auth_result.interaction_prompt_label);
  }
  if (!auth_result.interaction_prompt_type.empty()) {
    fields->emplace("input_type", auth_result.interaction_prompt_type);
  }
  if (!auth_result.interaction_group_options.empty()) {
    fields->emplace("options", auth_result.interaction_group_options);
  }
  return true;
}

protocol::ProtocolSessionOptions make_protocol_options(
    const VpnEngineConfig &config,
    const protocol::ParsedVpnUrl &parsed,
    const NativeVpnEngineDependencies &dependencies) {
  protocol::ProtocolSessionOptions options;
  options.server = parsed;
  options.username = config.username;
  options.password = config.password;
  options.useragent = config.useragent;
  options.auth_group = config.auth_group;
  options.csd_wrapper = config.csd_wrapper;
  options.dtls_mode = dtls_mode_from_config(config);
  options.disable_dtls = options.dtls_mode == protocol::DtlsMode::Disabled;
  options.auto_reconnect = config.auto_reconnect;
  options.max_reconnects = config.auto_reconnect
                                ? (config.retry_limit < 0 ? 0
                                                          : config.retry_limit)
                                : 0;
  options.mtu_fallback =
      (config.mtu >= 576 && config.mtu <= 1500) ? config.mtu : 1290;
  options.auth_interaction_handler = dependencies.auth_interaction_handler;
  if (dependencies.protocol_options_configurator) {
    dependencies.protocol_options_configurator(&options);
  }
  return options;
}

} // namespace

NativeHandshakeJob::NativeHandshakeJob(
    VpnEngineConfig config, NativeVpnEngineDependencies dependencies)
    : config_(std::move(config)), dependencies_(std::move(dependencies)) {}

ValidationResult NativeHandshakeJob::run(std::stop_token stop,
                                         NativeHandshakeResult *out) {
  if (out) {
    *out = {};
  }
  if (stop.stop_requested()) {
    return cancelled();
  }

  ValidationResult validation = validate_native_config(config_);
  if (!validation.ok) {
    return validation;
  }

  protocol::ParsedVpnUrl parsed;
  validation = protocol::parse_vpn_url(config_.server, &parsed);
  if (!validation.ok) {
    return validation;
  }

  std::unique_ptr<protocol::ProtocolTransport> transport;
  try {
    if (dependencies_.transport_factory) {
      transport = dependencies_.transport_factory();
    }
  } catch (const std::exception &e) {
    return invalid("native_transport_factory_failed", e.what());
  } catch (...) {
    return invalid("native_transport_factory_failed",
                   "Native transport factory failed.");
  }

  if (!transport) {
    return native_transport_unimplemented();
  }

  auto options = make_protocol_options(config_, parsed, dependencies_);
  auto protocol_session =
      std::make_unique<protocol::ProtocolSession>(options, transport.get());

  emit_event("native.starting", "info", "native VPN engine starting",
             {{"host", parsed.host}, {"port", std::to_string(parsed.port)}});
  emit_event("auth.started", "info", "password auth started");

  if (stop.stop_requested()) {
    transport->disconnect();
    return cancelled();
  }

  ValidationResult auth = protocol_session->authenticate();
  if (!auth.ok) {
    if (auth.code == "csd_required_unsupported") {
      emit_event("csd.required_unsupported", "warning",
                 "AnyConnect host-scan is required but unsupported",
                 {{"code", auth.code}});
    }
    std::string interaction_type;
    std::map<std::string, std::string> interaction_fields;
    if (make_auth_interaction_event(auth, protocol_session->last_auth_result(),
                                    &interaction_type, &interaction_fields)) {
      emit_event(std::move(interaction_type), "warning", auth.message,
                 std::move(interaction_fields));
    }
    emit_event("auth.failed", "error", auth.message, {{"code", auth.code}});
    return auth;
  }
  emit_event("auth.succeeded", "info", "password auth succeeded");

  if (stop.stop_requested()) {
    transport->disconnect();
    return cancelled();
  }

  TunnelMetadata metadata;
  ValidationResult cstp = protocol_session->connect_cstp(&metadata);
  if (!cstp.ok) {
    emit_event("cstp.failed", "error", cstp.message, {{"code", cstp.code}});
    transport->disconnect();
    return cstp;
  }

  emit_event("cstp.connected", "info", "CSTP connect succeeded",
             {{"interface", metadata.interface_name},
              {"internal_ip", metadata.internal_ip4_address}});

  emit_event("dtls.policy.decision", "info", "native DTLS policy decided",
             dtls_event_fields(metadata));

  if (metadata.active_data_channel == "dtls" &&
      metadata.dtls_state ==
          protocol::dtls_transport_state_to_string(
              protocol::DtlsTransportState::attempted_and_connected)) {
    emit_event("dtls.connected", "info", "DTLS data channel connected",
               dtls_event_fields(metadata));
  } else if (dtls_mode_from_config(config_) != protocol::DtlsMode::Disabled) {
    const std::string message =
        metadata.dtls_fallback_reason.empty()
            ? "native DTLS unavailable; using CSTP/TLS"
            : metadata.dtls_fallback_reason;
    auto fields = dtls_event_fields(metadata);
    fields.emplace("code", "dtls_unavailable");
    emit_event("dtls.unavailable", "warning", message, std::move(fields));
  }

  if (out) {
    out->metadata = std::move(metadata);
    out->transport = std::move(transport);
    out->session = std::move(protocol_session);
  }
  return {};
}

void NativeHandshakeJob::emit_event(
    std::string type, std::string level, std::string message,
    std::map<std::string, std::string> fields) {
  if (!dependencies_.event_sink) {
    return;
  }
  VpnEngineEvent event;
  event.type = std::move(type);
  event.level = std::move(level);
  event.message = std::move(message);
  event.fields = std::move(fields);
  dependencies_.event_sink->emit(event);
}

} // namespace vpn_engine
} // namespace exv
