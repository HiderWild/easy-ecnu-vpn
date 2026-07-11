#pragma once

#include <cstdint>
#include <string>

namespace exv::core {

enum class DesiredVpnIntent { Disconnect, Connect };

struct PendingConnectRequest {
  std::string profile_id;
  std::string server;
  bool has_password = false;
};

inline bool same_pending_connect_request(const PendingConnectRequest &lhs,
                                         const PendingConnectRequest &rhs) {
  return lhs.profile_id == rhs.profile_id && lhs.server == rhs.server &&
         lhs.has_password == rhs.has_password;
}

struct VpnWorkflowIntent {
  DesiredVpnIntent desired = DesiredVpnIntent::Disconnect;
  std::uint64_t epoch = 0;
  PendingConnectRequest pending_connect;
};

} // namespace exv::core
