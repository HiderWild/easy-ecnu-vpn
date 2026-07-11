#include "core/app_api/desktop_status_presenter.hpp"

#include "core/app_api/desktop_json.hpp"
#include "core/config/config_api.hpp"
#include "core/config/config_platform_view.hpp"
#include "core/network/virtual_network_status.hpp"
#include "core/tunnel_controller/connect_progress_json.hpp"
#include "platform/common/driver_status.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/runtime_status.hpp"
#include "platform/common/service_status.hpp"

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <utility>

namespace exv {
namespace app_api {
namespace {

using Clock = std::chrono::steady_clock;
constexpr auto kVirtualNetworkProbeCacheTtl = std::chrono::seconds(10);

struct VirtualNetworkProbeCacheEntry {
  nlohmann::json fields;
  Clock::time_point updated_at;
};

struct VirtualNetworkProbeState {
  std::mutex mutex;
  std::map<std::string, VirtualNetworkProbeCacheEntry> cache;
  std::set<std::string> in_flight;
  std::deque<nlohmann::json> pending_events;
};

VirtualNetworkProbeState &virtual_network_probe_state() {
  static VirtualNetworkProbeState state;
  return state;
}

bool cache_entry_fresh(const VirtualNetworkProbeCacheEntry &entry,
                       Clock::time_point now) {
  return now - entry.updated_at < kVirtualNetworkProbeCacheTtl;
}

nlohmann::json default_virtual_network_fields() {
  return nlohmann::json{{"upstream_virtual_detected", false},
                        {"upstream_virtual_adapters", nlohmann::json::array()},
                        {"upstream_virtual_message", ""},
                        {"route_policy", "normal"}};
}

void merge_virtual_network_fields(nlohmann::json &status,
                                  const nlohmann::json &fields) {
  for (const auto *key : {"upstream_virtual_detected",
                          "upstream_virtual_adapters",
                          "upstream_virtual_message",
                          "route_policy"}) {
    if (fields.contains(key)) {
      status[key] = fields.at(key);
    }
  }
}

void add_default_virtual_network_fields(nlohmann::json &status) {
  merge_virtual_network_fields(status, default_virtual_network_fields());
}

nlohmann::json probe_virtual_network_fields(
    const std::string &interface_name) {
  nlohmann::json fields = default_virtual_network_fields();
  try {
    virtual_network::add_status_fields(fields, interface_name);
  } catch (...) {
    fields = default_virtual_network_fields();
  }
  return fields;
}

void request_virtual_network_probe(const std::string &interface_name) {
  auto &state = virtual_network_probe_state();
  const std::string key = interface_name;
  const auto now = Clock::now();
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto cached = state.cache.find(key);
    if (cached != state.cache.end() &&
        cache_entry_fresh(cached->second, now)) {
      return;
    }
    if (state.in_flight.count(key) != 0) {
      return;
    }
    state.in_flight.insert(key);
  }

  std::thread([key, interface_name] {
    nlohmann::json fields = probe_virtual_network_fields(interface_name);
    nlohmann::json event = fields;
    event["Finnished"] = true;

    auto &state = virtual_network_probe_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.cache[key] = VirtualNetworkProbeCacheEntry{fields, Clock::now()};
    state.pending_events.push_back(std::move(event));
    state.in_flight.erase(key);
  }).detach();
}

void add_cached_virtual_network_fields(nlohmann::json &status,
                                       const std::string &interface_name) {
  auto &state = virtual_network_probe_state();
  nlohmann::json fields = default_virtual_network_fields();
  const std::string key = interface_name;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    const auto cached = state.cache.find(key);
    if (cached != state.cache.end()) {
      fields = cached->second.fields;
    }
  }

  merge_virtual_network_fields(status, fields);
  request_virtual_network_probe(interface_name);
}

} // namespace

nlohmann::json frontend_status_from_helper(const nlohmann::json &helper_resp,
                                           const Config &cfg) {
  const bool running = json_bool(helper_resp, "running", false);
  const bool network_ready = json_bool(helper_resp, "network_ready", false);
  nlohmann::json j;
  j["connected"] = running && network_ready;
  j["process_running"] = running;
  j["server"] = json_string(helper_resp, "server", cfg.server);
  j["username"] = cfg.username;
  j["pid"] = json_int(helper_resp, "pid", -1);
  j["network_ready"] = network_ready;
  j["interface"] = json_string(helper_resp, "interface");
  j["internal_ip"] = json_string(helper_resp, "internal_ip");
  j["route_count"] =
      json_int(helper_resp, "route_count", static_cast<int>(cfg.routes.size()));
  j["mtu"] = cfg.mtu;
  j["uptime_seconds"] = 0;
  j["rx_bytes"] = json_u64(helper_resp, "rx_bytes", 0);
  j["tx_bytes"] = json_u64(helper_resp, "tx_bytes", 0);
  add_cached_virtual_network_fields(j, json_string(j, "interface"));
  return j;
}

nlohmann::json disconnected_status(const Config &cfg) {
  nlohmann::json j{{"connected", false},
                   {"process_running", false},
                   {"server", cfg.server},
                   {"username", cfg.username},
                   {"pid", -1},
                   {"network_ready", false},
                   {"interface", ""},
                   {"internal_ip", ""},
                   {"dtls_mode", "auto"},
                   {"active_data_channel", "cstp_tls"},
                   {"dtls_state", "disabled"},
                   {"dtls_fallback_reason", ""},
                   {"dtls_fallback_count", 0},
                   {"route_count", static_cast<int>(cfg.routes.size())},
                   {"mtu", cfg.mtu},
                   {"uptime_seconds", 0},
                   {"rx_bytes", 0},
                   {"tx_bytes", 0}};
  add_cached_virtual_network_fields(j, "");
  return j;
}

nlohmann::json frontend_status_from_snapshot_json(
    const nlohmann::json &snapshot, const Config &cfg) {
  const std::string iface = json_string(snapshot, "interface");
  const bool running = json_bool(snapshot, "running", false);
  const bool network_ready = json_bool(snapshot, "network_ready", false);
  uint64_t rx_bytes = 0;
  uint64_t tx_bytes = 0;
  if (network_ready && !iface.empty()) {
    platform::get_interface_traffic(iface, &rx_bytes, &tx_bytes);
  }

  nlohmann::json j;
  j["connected"] = running && network_ready;
  j["process_running"] = running;
  j["server"] = cfg.server;
  j["username"] = cfg.username;
  j["pid"] = json_int(snapshot, "pid", -1);
  j["network_ready"] = network_ready;
  j["interface"] = iface;
  j["internal_ip"] = json_string(snapshot, "internal_ip");
  j["route_count"] = static_cast<int>(cfg.routes.size());
  j["mtu"] = cfg.mtu;
  j["uptime_seconds"] = 0;
  j["rx_bytes"] = rx_bytes;
  j["tx_bytes"] = tx_bytes;
  add_cached_virtual_network_fields(j, iface);
  return j;
}

nlohmann::json auth_config(const Config &cfg) {
  return nlohmann::json{{"server", cfg.server},
                        {"username", cfg.username},
                        {"password", ""},
                        {"password_stored", !cfg.password.empty()},
                        {"user_agent", cfg.useragent},
                        {"remember_password", cfg.remember_password}};
}

nlohmann::json settings_config(const Config &cfg) {
  std::string extra_args;
  for (size_t i = 0; i < cfg.extra_args.size(); ++i) {
    if (i > 0) {
      extra_args += " ";
    }
    extra_args += cfg.extra_args[i];
  }

  return nlohmann::json{{"mtu", cfg.mtu},
                        {"dtls", !cfg.disable_dtls},
                        {"dtls_mode", cfg.dtls_mode},
                        {"extra_args", extra_args},
                        {"log_path", cfg.log_file},
                        {"vpn_engine", cfg.vpn_engine},
                        {"windows_tunnel_driver", cfg.windows_tunnel_driver},
                        {"windows_tap_interface", cfg.windows_tap_interface},
                        {"auto_reconnect", cfg.auto_reconnect},
                        {"minimal_mode", cfg.minimal_mode},
                        {"service_install_prompt_seen",
                         cfg.service_install_prompt_seen},
                        {"minimal_install_service_before_connect",
                         cfg.minimal_install_service_before_connect}};
}

nlohmann::json routes_json(const Config &cfg) {
  nlohmann::json arr = nlohmann::json::array();
  for (const auto &route : cfg.routes) {
    arr.push_back({{"cidr", route}});
  }
  return arr;
}

nlohmann::json key_status_json() {
  const std::string status = config_api::key_status();
  return nlohmann::json{{"present", status == "valid"},
                        {"fingerprint", status == "valid"
                                            ? nlohmann::json("active")
                                            : nlohmann::json(nullptr)},
                        {"status", status}};
}

nlohmann::json service_status_json() {
  return platform::service_status_to_json(platform::current_service_status());
}

nlohmann::json runtime_status_json(const Config &cfg) {
  return platform::runtime_status_json(config::to_platform_config_view(cfg));
}

nlohmann::json frontend_status_from_controller_snapshot(
    const exv::core::TunnelStatusSnapshot &snap, const Config &cfg) {
  const bool running = snap.phase != exv::core::TunnelPhase::Idle &&
                       snap.phase != exv::core::TunnelPhase::Failed;
  const bool connected = running && snap.network_ready;

  nlohmann::json j;
  j["connected"] = connected;
  j["process_running"] = running;
  j["server"] = snap.server.empty() ? cfg.server : snap.server;
  j["username"] = cfg.username;
  j["pid"] = -1;
  j["network_ready"] = snap.network_ready;
  j["interface"] = snap.interface_name;
  j["internal_ip"] = snap.internal_ip;
  j["dtls_mode"] = snap.dtls_mode;
  j["active_data_channel"] = snap.active_data_channel;
  j["dtls_state"] = snap.dtls_state;
  j["dtls_fallback_reason"] = snap.dtls_fallback_reason;
  j["dtls_fallback_count"] = snap.dtls_fallback_count;
  j["route_count"] = static_cast<int>(cfg.routes.size());
  j["mtu"] = cfg.mtu;
  j["uptime_seconds"] = 0;
  j["rx_bytes"] = 0;
  j["tx_bytes"] = 0;
  if (snap.last_error.has_value()) {
    j["error"] = snap.last_error->message;
    j["error_code"] = snap.last_error->code;
    j["error_recoverable"] = snap.last_error->recoverable;
  }
  if (snap.reconnect.has_value()) {
    j["reconnect_attempt"] = snap.reconnect->attempt;
    j["reconnect_next_retry_ms"] = snap.reconnect->next_retry_ms;
  }
  j["auto_reconnect"] = snap.auto_reconnect;
  j["phase"] = exv::core::tunnel_phase_wire_name(snap.phase);
  j["connect_progress"] =
      exv::core::connect_progress_to_json(snap.connect_progress);
  add_cached_virtual_network_fields(j, snap.interface_name);
  return j;
}

nlohmann::json helper_current_instance_from_controller_snapshot(
    const exv::core::TunnelStatusSnapshot &snap) {
  nlohmann::json j;
  j["mode"] = snap.helper_mode;
  j["status"] = snap.helper_status;
  j["lease_active"] = snap.core_lease_active;
  j["session_active"] = snap.session_active;
  j["endpoint"] = snap.helper_endpoint;
  j["phase"] = exv::core::tunnel_phase_wire_name(snap.phase);
  return j;
}

nlohmann::json driver_status_json(const Config &cfg) {
  return platform::driver_status_json(config::to_platform_config_view(cfg));
}

nlohmann::json install_driver(const Config &cfg, const nlohmann::json &payload) {
  return platform::install_driver(config::to_platform_config_view(cfg), payload);
}

nlohmann::json drain_virtual_network_status_events() {
  auto &state = virtual_network_probe_state();
  nlohmann::json events = nlohmann::json::array();
  std::lock_guard<std::mutex> lock(state.mutex);
  while (!state.pending_events.empty()) {
    events.push_back(std::move(state.pending_events.front()));
    state.pending_events.pop_front();
  }
  return events;
}

void reset_virtual_network_probe_state_for_testing() {
  auto &state = virtual_network_probe_state();
  std::lock_guard<std::mutex> lock(state.mutex);
  state.cache.clear();
  state.in_flight.clear();
  state.pending_events.clear();
}

void expire_virtual_network_probe_cache_for_testing() {
  auto &state = virtual_network_probe_state();
  std::lock_guard<std::mutex> lock(state.mutex);
  for (auto &[_, entry] : state.cache) {
    entry.updated_at -= kVirtualNetworkProbeCacheTtl + std::chrono::seconds(1);
  }
}

} // namespace app_api
} // namespace exv
