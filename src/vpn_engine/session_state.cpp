#include "vpn_engine/session_state.hpp"

#include <utility>

namespace exv {
namespace vpn_engine {

namespace {

std::string bytes_to_hex(const std::vector<std::uint8_t> &bytes) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4) & 0x0F]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
}

} // namespace

bool SessionState::network_ready() const {
  return phase == SessionPhase::packet_loop && tunnel_ready && packet_loop_ready;
}

void SessionState::auth_started() {
  phase = SessionPhase::authenticating;
  failure_code.clear();
  failure_message.clear();
}

void SessionState::auth_succeeded() {
  phase = SessionPhase::authenticated;
  failure_code.clear();
  failure_message.clear();
}

void SessionState::tunnel_configured(const TunnelMetadata &metadata) {
  tunnel = metadata;
  tunnel_ready = true;
  phase = SessionPhase::configuring_network;
}

void SessionState::packet_loop_started() {
  packet_loop_ready = true;
  phase = SessionPhase::packet_loop;
}

void SessionState::stopped() {
  phase = SessionPhase::stopped;
}

void SessionState::failed(const std::string &code, const std::string &message) {
  phase = SessionPhase::failed;
  failure_code = code;
  failure_message = message;
}

nlohmann::json session_phase_to_json(SessionPhase phase) {
  switch (phase) {
  case SessionPhase::idle:
    return "idle";
  case SessionPhase::authenticating:
    return "authenticating";
  case SessionPhase::authenticated:
    return "authenticated";
  case SessionPhase::configuring_network:
    return "configuring_network";
  case SessionPhase::packet_loop:
    return "packet_loop";
  case SessionPhase::reconnecting:
    return "reconnecting";
  case SessionPhase::stopping:
    return "stopping";
  case SessionPhase::stopped:
    return "stopped";
  case SessionPhase::failed:
    return "failed";
  }

  return "idle";
}

nlohmann::json tunnel_metadata_to_json(const TunnelMetadata &metadata) {
  return nlohmann::json{{"interface_name", metadata.interface_name},
                        {"interface_index", metadata.interface_index},
                        {"internal_ip4_address", metadata.internal_ip4_address},
                        {"internal_ip4_netmask", metadata.internal_ip4_netmask},
                        {"ip6_address", metadata.ip6_address},
                        {"ip6_prefix", metadata.ip6_prefix},
                        {"mtu", metadata.mtu},
                        {"routes", metadata.routes},
                        {"split_include_routes", metadata.split_include_routes},
                        {"split_exclude_routes", metadata.split_exclude_routes},
                        {"server_bypass_ips", metadata.server_bypass_ips},
                        {"dtls_mode", metadata.dtls_mode},
                        {"active_data_channel", metadata.active_data_channel},
                        {"dtls_state", metadata.dtls_state},
                        {"dtls_fallback_reason",
                         metadata.dtls_fallback_reason},
                        {"dtls_fallback_count", metadata.dtls_fallback_count},
                        {"dns_servers", metadata.dns_servers},
                        {"nbns_servers", metadata.nbns_servers},
                        {"default_domain", metadata.default_domain},
                        {"search_domains", metadata.search_domains},
                        {"tunnel_all_dns", metadata.tunnel_all_dns},
                        {"banner", metadata.banner},
                        {"keepalive_seconds", metadata.keepalive_seconds},
                        {"dpd_seconds", metadata.dpd_seconds},
                        {"rekey_seconds", metadata.rekey_seconds},
                        {"rekey_method", metadata.rekey_method},
                        {"lease_duration_seconds",
                         metadata.lease_duration_seconds},
                        {"idle_timeout_seconds", metadata.idle_timeout_seconds},
                        {"session_timeout_seconds",
                         metadata.session_timeout_seconds},
                        {"disconnected_timeout_seconds",
                         metadata.disconnected_timeout_seconds},
                        {"dtls_mtu", metadata.dtls_mtu},
                        {"dtls_port", metadata.dtls_port},
                        {"dtls_session_id", metadata.dtls_session_id},
                        {"dtls_cipher_suite", metadata.dtls_cipher_suite},
                        {"dtls12_cipher_suite", metadata.dtls12_cipher_suite},
                        {"dtls_master_secret_hex",
                         bytes_to_hex(metadata.dtls_master_secret)},
                        {"content_encoding", metadata.content_encoding}};
}

nlohmann::json session_state_to_json(const SessionState &state) {
  return nlohmann::json{
      {"phase", session_phase_to_json(state.phase)},
      {"tunnel_ready", state.tunnel_ready},
      {"packet_loop_ready", state.packet_loop_ready},
      {"network_ready", state.network_ready()},
      {"tunnel_metadata", tunnel_metadata_to_json(state.tunnel)},
      {"last_event_message", state.last_event_message},
      {"failure",
       nlohmann::json{{"code", state.failure_code},
                     {"message", state.failure_message}}},
  };
}

} // namespace vpn_engine
} // namespace exv
