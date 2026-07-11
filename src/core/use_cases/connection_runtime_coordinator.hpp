#pragma once

#include "core/tunnel_controller/tunnel_state.hpp"

#include <cstdint>
#include <mutex>
#include <string>

namespace exv::core {

struct ConnectionRuntimeIdentity {
  std::uint64_t runtime_epoch = 0;
  std::uint64_t controller_id = 0;
};

class ConnectionRuntimeCoordinator {
public:
  ConnectionRuntimeIdentity begin_runtime(const std::string &origin);
  void retire_controller(std::uint64_t controller_id,
                         const std::string &reason);
  bool accepts_status(const TunnelStatusSnapshot &snapshot) const;
  ConnectionRuntimeIdentity current_identity() const;

private:
  mutable std::mutex mutex_;
  std::uint64_t next_runtime_epoch_ = 0;
  std::uint64_t next_controller_id_ = 0;
  ConnectionRuntimeIdentity current_;
};

} // namespace exv::core
