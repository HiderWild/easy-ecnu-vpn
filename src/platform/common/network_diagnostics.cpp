#include "platform/common/network_diagnostics.hpp"

#ifdef _WIN32
#include "platform/win32/network_diagnostics.hpp"
#endif

namespace exv::platform {

std::vector<std::pair<std::string, std::string>>
network_diagnostics_route_snapshot_fields(const std::string& vpn_server) {
#ifdef _WIN32
  return exv::platform::win32::network_adapter_route_snapshot_fields(
      vpn_server, exv::platform::win32::snapshot_network_adapter_result());
#else
  return {{"proxy_tun_detected", "false"},
          {"vpn_server", vpn_server},
          {"adapter_count", "0"},
          {"snapshot_status", "unsupported"}};
#endif
}

} // namespace exv::platform
