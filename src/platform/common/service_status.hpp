#pragma once

#include "platform/common/status_models.hpp"

#include <string>

namespace exv {
namespace platform {

ServiceStatusSnapshot current_service_status();

struct ServiceStartResult {
  bool accepted = false;
  std::string code;
  std::string message;
  int native_code = 0;
  std::string native_message;
};

// Attempt to start an installed-but-not-running helper service (Windows
// StartService / launchctl kickstart / systemctl start). Returns accepted=true
// if the start command was accepted. The caller re-probes
// current_service_status() afterward to confirm availability.
ServiceStartResult try_start_helper_service();

} // namespace platform
} // namespace exv
