#pragma once

#include <string>
#include <utility>
#include <vector>

namespace exv::platform {

std::vector<std::pair<std::string, std::string>>
network_diagnostics_route_snapshot_fields(const std::string& vpn_server);

} // namespace exv::platform
