#pragma once

#include "core/tunnel_controller/tunnel_controller_fwd.hpp"
#include "core/tunnel_controller/vpn_connect_job.hpp"
#include "core/use_cases/use_case_result.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace exv::helper {
class HelperClient;
} // namespace exv::helper

namespace exv::core {

// TunnelUseCases is the single, process-wide source of truth for the VPN
// tunnel runtime that the desktop (core/app_api) and native (core/rpc)
// entrypoints share.  It owns the HelperConnector + HelperClient + network
// ops + TunnelController lifecycle so that the two entrypoints can no longer
// drift into separate controller instances.
//
// Business-ization note (Core Architecture Normalization Plan): action
// handlers must route tunnel runtime ownership through this use case instead
// of holding their own controllers.
//
// CONCURRENCY-SEAM: this type is the single chokepoint where tunnel-runtime
// synchronization belongs.  Locking is intentionally deferred to the dedicated
// concurrency-hardening pass; this phase only unifies ownership.
class TunnelUseCases {
public:
  TunnelUseCases();
  ~TunnelUseCases();

  TunnelUseCases(const TunnelUseCases &) = delete;
  TunnelUseCases &operator=(const TunnelUseCases &) = delete;

  // Absolute path to the helper binary that ships next to the exv executable.
  static std::string helper_binary_next_to_exv();

  // Lazily construct (or return the existing) shared TunnelController, wiring a
  // transient helper connection.  Returns nullptr if helper bring-up fails.
  std::shared_ptr<exv::core::TunnelController>
  ensure_controller(const std::string &endpoint_override = "");

  // Return the active controller without attempting to create one.
  std::shared_ptr<exv::core::TunnelController> controller_if_exists() const;

  // Return the helper client backing the active controller, if any.
  std::shared_ptr<exv::helper::HelperClient> current_helper_client() const;

  // Tear down the controller and its helper connection, clearing init state.
  void reset_controller();

  // --- Desktop connect-job ownership (relocated from desktop_vpn_actions.cpp) ---

  // Provide guarded access to the shared VpnConnectJobOwner.  The returned
  // reference is valid for the lifetime of the process-global singleton.
  // Callers must hold connect_jobs_mutex() while accessing it.
  std::mutex &connect_jobs_mutex();
  VpnConnectJobOwner &connect_jobs();

  // Connect-error state (last failure JSON shown to the desktop UI).
  std::optional<nlohmann::json> connect_error() const;
  void set_connect_error(nlohmann::json failure);
  void clear_connect_error();

  // Shut down the connect-job owner (joins background threads).
  void shutdown_connect_jobs(const std::string &reason);

  // Human-readable reason the most recent controller bring-up failed.
  std::string controller_init_error() const;

private:
  struct State;
  std::unique_ptr<State> state_;
};

// Process-global shared instance.  Both the desktop and native VPN handlers
// resolve the controller through this accessor so there is exactly one
// TunnelController in the core process.
TunnelUseCases &tunnel_use_cases();

} // namespace exv::core
