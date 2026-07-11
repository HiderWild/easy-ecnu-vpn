#include "core/use_cases/connection_runtime_coordinator.hpp"

#include "observability/log_facade.hpp"

#include <string>

namespace exv::core {

ConnectionRuntimeIdentity ConnectionRuntimeCoordinator::begin_runtime(
    const std::string &origin) {
  std::lock_guard<std::mutex> lock(mutex_);
  current_.runtime_epoch = ++next_runtime_epoch_;
  current_.controller_id = ++next_controller_id_;
  exv::observability::LogFacade::event(
      "INFO", "tunnel", "connection.runtime.epoch_started",
      "Started VPN connection runtime epoch",
      {{"runtime_epoch", std::to_string(current_.runtime_epoch)},
       {"controller_id", std::to_string(current_.controller_id)},
       {"origin", origin}});
  return current_;
}

void ConnectionRuntimeCoordinator::retire_controller(
    std::uint64_t controller_id, const std::string &reason) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (controller_id != 0 && controller_id == current_.controller_id) {
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "connection.runtime.controller_retired",
        "Retired VPN connection controller",
        {{"runtime_epoch", std::to_string(current_.runtime_epoch)},
         {"controller_id", std::to_string(controller_id)},
         {"reason", reason}});
    current_.controller_id = 0;
  }
}

bool ConnectionRuntimeCoordinator::accepts_status(
    const TunnelStatusSnapshot &snapshot) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return snapshot.runtime_epoch != 0 &&
         snapshot.runtime_epoch == current_.runtime_epoch &&
         snapshot.controller_id != 0 &&
         snapshot.controller_id == current_.controller_id;
}

ConnectionRuntimeIdentity ConnectionRuntimeCoordinator::current_identity()
    const {
  std::lock_guard<std::mutex> lock(mutex_);
  return current_;
}

} // namespace exv::core
