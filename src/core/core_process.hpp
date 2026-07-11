#pragma once
#include "core/tunnel_controller/tunnel_state.hpp"

#include <optional>
#include <string>
#include <vector>

namespace exv::core {

// Entry point for `exv --mode=core` long-running process.
// Reads JSON-RPC requests from stdin (if use_stdin=true) or pipe only (daemon mode),
// dispatches them through AppRpcDispatcher, and writes responses to stdout.
// Status change events are pushed as JSON lines to stdout.
//
// Returns 0 on clean shutdown (SIGTERM/SIGINT), non-zero on fatal error.
int core_process_main(const std::string& config_dir,
                      const std::string& home_dir,
                      bool use_stdin = false);

bool should_inspect_helper_for_registry(
    const std::optional<TunnelStatusSnapshot>& status);

} // namespace exv::core
