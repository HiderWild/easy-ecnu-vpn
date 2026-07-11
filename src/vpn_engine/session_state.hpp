#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {

// Stable session lifecycle phases for the native engine.
//
// JSON encoding: session_phase_to_json() returns a string with the same name as
// the enumerator (e.g. "idle", "packet_loop").
enum class SessionPhase {
  idle,
  authenticating,
  authenticated,
  configuring_network,
  packet_loop,
  reconnecting,
  stopping,
  stopped,
  failed,
};

struct TunnelMetadata {
  std::string interface_name;
  int interface_index = -1;
  std::string internal_ip4_address;
  std::string internal_ip4_netmask;
  std::string ip6_address;
  int ip6_prefix = 0;
  int mtu = 1290;
  std::vector<std::string> routes;
  std::vector<std::string> split_include_routes;
  std::vector<std::string> split_exclude_routes;
  std::vector<std::string> server_bypass_ips;
  std::string dtls_mode = "auto";
  std::string active_data_channel = "cstp_tls";
  std::string dtls_state = "disabled";
  std::string dtls_fallback_reason;
  int dtls_fallback_count = 0;
  std::vector<std::string> dns_servers;
  std::vector<std::string> nbns_servers;
  std::string default_domain;
  std::vector<std::string> search_domains;
  bool tunnel_all_dns = false;
  std::string banner;
  int keepalive_seconds = 0;
  int dpd_seconds = 0;
  int rekey_seconds = 0;
  std::string rekey_method;
  int lease_duration_seconds = 0;
  int idle_timeout_seconds = 0;
  int session_timeout_seconds = 0;
  int disconnected_timeout_seconds = 0;
  int dtls_mtu = 0;
  int dtls_port = 0;
  std::string dtls_session_id;
  std::string dtls_cipher_suite;
  std::string dtls12_cipher_suite;
  std::vector<std::uint8_t> dtls_master_secret;
  std::string content_encoding;
};

// SessionState is a clean-room state model used by the native engine boundary.
//
// Stable JSON schema (session_state_to_json):
// - phase: string (see SessionPhase)
// - tunnel_ready: bool
// - packet_loop_ready: bool
// - network_ready: bool (true only when phase == packet_loop AND both ready)
// - tunnel_metadata: object (see tunnel_metadata_to_json)
// - last_event_message: string (UTF-8 preserved as-is)
// - failure: { code: string, message: string }
//
// Notes:
// - No OpenConnect process/pid field exists or is required.
struct SessionState {
  SessionPhase phase = SessionPhase::idle;

  TunnelMetadata tunnel;
  bool tunnel_ready = false;
  bool packet_loop_ready = false;

  std::string last_event_message;

  std::string failure_code;
  std::string failure_message;

  bool network_ready() const;

  void auth_started();
  void auth_succeeded();
  void tunnel_configured(const TunnelMetadata &metadata);
  void packet_loop_started();
  void stopped();
  void failed(const std::string &code, const std::string &message);
};

nlohmann::json session_phase_to_json(SessionPhase phase);
nlohmann::json tunnel_metadata_to_json(const TunnelMetadata &metadata);
nlohmann::json session_state_to_json(const SessionState &state);

} // namespace vpn_engine
} // namespace exv
