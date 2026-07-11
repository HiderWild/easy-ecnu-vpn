#pragma once

#include <string>
#include <utility>
#include <vector>

namespace exv::platform::win32 {

struct NetworkAdapterSnapshot {
  std::string name;
  std::string interface_type;
  int interface_index = 0;
  int mtu = 0;
};

struct NetworkAdapterSnapshotResult {
  std::vector<NetworkAdapterSnapshot> adapters;
  bool ok = true;
  unsigned long error_code = 0;
};

bool is_known_proxy_tun(const NetworkAdapterSnapshot &adapter);
std::vector<std::pair<std::string, std::string>>
network_adapter_route_snapshot_fields(
    const std::string &vpn_server,
    const NetworkAdapterSnapshotResult &snapshot_result);
NetworkAdapterSnapshotResult snapshot_network_adapter_result();
std::vector<NetworkAdapterSnapshot> snapshot_network_adapters();

} // namespace exv::platform::win32
