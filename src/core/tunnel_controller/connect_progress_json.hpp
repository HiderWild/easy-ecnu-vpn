#pragma once

#include "core/tunnel_controller/connect_progress.hpp"

#include <nlohmann/json.hpp>

namespace exv::core {

nlohmann::json connect_progress_to_json(const ConnectProgress &progress);

} // namespace exv::core
