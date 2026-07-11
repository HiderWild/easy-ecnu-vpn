#pragma once

#include "platform/common/status_models.hpp"

namespace exv {
namespace platform {

ServiceStatusSnapshot current_service_status();

// Attempt to start an installed-but-not-running helper service (Windows
// StartService / launchctl kickstart / systemctl start). Returns true if the
// start command was accepted. The caller re-probes current_service_status()
// afterward to confirm availability.
bool try_start_helper_service();

} // namespace platform
} // namespace exv
