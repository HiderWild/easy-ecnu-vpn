#pragma once

#include <string>
#include <vector>

namespace exv {
namespace platform {

struct ConfigView {
  std::string server;
  std::string username;
  int mtu = 1290;
  std::string useragent;
  bool disable_dtls = false;
  std::string dtls_mode = "auto";
  std::vector<std::string> extra_args;
  std::string log_file;
  std::string vpn_engine = "native";
  std::string windows_tunnel_driver = "auto";
  std::string windows_tap_interface;
};

} // namespace platform
} // namespace exv
