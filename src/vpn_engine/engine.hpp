#pragma once

#include <map>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {

struct VpnEngineConfig {
  std::string engine = "native";
  std::string server;
  std::string username;
  std::string password;
  std::string useragent;
  std::string auth_group;
  std::string csd_wrapper;
  int mtu = 1290;
  std::vector<std::string> routes;
  std::vector<std::string> server_bypass_ips;
  std::string windows_tunnel_driver = "auto";
  std::string windows_tap_interface;
  bool auto_reconnect = true;
  int retry_limit = 0;
  bool disable_dtls = false;
  std::string dtls_mode = "auto";
};

struct VpnEngineEvent {
  std::string type;
  std::string level = "info";
  std::string message;
  std::map<std::string, std::string> fields;
};

struct VpnEngineStatus {
  bool running = false;
  bool network_ready = false;
  int pid = -1;
  std::string interface_name;
  std::string internal_ip;
  std::string dtls_mode = "auto";
  std::string active_data_channel = "cstp_tls";
  std::string dtls_state = "disabled";
  std::string dtls_fallback_reason;
  int dtls_fallback_count = 0;
  std::string error_code;
  std::string error_message;
};

struct ValidationResult {
  bool ok = true;
  std::string code;
  std::string message;
};

class VpnEngineSession {
public:
  virtual ~VpnEngineSession() = default;

  virtual ValidationResult start() = 0;
  virtual void stop() = 0;
  virtual VpnEngineStatus status() const = 0;
};

} // namespace vpn_engine
} // namespace exv
