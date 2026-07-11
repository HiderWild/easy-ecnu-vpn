#pragma once

#include "core/tunnel_controller/tunnel_controller_fwd.hpp"
#include "core/tunnel_controller/tunnel_state.hpp"
#include "core/tunnel_controller/vpn_connect_job.hpp"
#include "core/use_cases/use_case_result.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace exv::helper {
class HelperClient;
} // namespace exv::helper

namespace exv::core {

struct TunnelRecoveryRequest;

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
  using StatusObserverId = std::uint64_t;
  using ConnectJobObserverId = std::uint64_t;
  using StatusObserver =
      std::function<void(const exv::core::TunnelStatusSnapshot &)>;
  using ConnectJobObserver =
      std::function<void(const exv::core::VpnConnectJobState &)>;

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
  void reset_controller(bool release_active_lease = true);

  StatusObserverId add_status_observer(StatusObserver observer);
  void remove_status_observer(StatusObserverId id);
  ConnectJobObserverId add_connect_job_observer(ConnectJobObserver observer);
  void remove_connect_job_observer(ConnectJobObserverId id);
  std::optional<TunnelStatusSnapshot> latest_status() const;
  VpnConnectJobState latest_connect_job() const;

  bool acquire_active_tunnel_lease(const std::string &owner,
                                   const std::string &profile_id,
                                   std::string *error_code,
                                   std::string *error_message);
  void release_active_tunnel_lease();
  std::string active_tunnel_lease_id() const;
  void track_active_connection_attempt(const std::string &config_dir,
                                       const std::string &attempt_id);
  bool reconcile_terminal_runtime(const TunnelStatusSnapshot &snapshot,
                                  const std::string &reason);
  bool reconcile_terminal_runtime(const std::string &reason);
  bool reconcile_terminal_connection_attempt(
      const TunnelStatusSnapshot &snapshot, const std::string &config_dir,
      const std::string &attempt_id, int owner_pid, const std::string &reason);
  bool reconcile_terminal_connection_attempt(const std::string &config_dir,
                                             const std::string &attempt_id,
                                             int owner_pid,
                                             const std::string &reason);
  void request_recovery(const TunnelRecoveryRequest &request);
  bool current_runtime_is_connected() const;
  bool current_runtime_is_connecting_or_recovering() const;

  // --- Desktop connect-job ownership (relocated from desktop_vpn_actions.cpp) ---

  // Provide access to the shared self-synchronized VpnConnectJobOwner.  The
  // returned reference is valid for the lifetime of the process-global
  // singleton.
  std::mutex &connect_jobs_mutex();
  VpnConnectJobOwner &connect_jobs();

  // Connect-error state (last failure JSON shown to the desktop UI).
  std::optional<nlohmann::json> connect_error() const;
  void set_connect_error(nlohmann::json failure);
  void set_connect_error(std::uint64_t epoch, nlohmann::json failure);
  void clear_connect_error();
  void clear_connect_error(std::uint64_t epoch);

  // Shut down the connect-job owner (joins background threads).
  void shutdown_connect_jobs(const std::string &reason);

  // Human-readable reason the most recent controller bring-up failed.
  std::string controller_init_error() const;

private:
  struct State;
  void publish_status(const TunnelStatusSnapshot &snapshot);
  void publish_status_from_controller(std::uint64_t controller_id,
                                      const TunnelStatusSnapshot &snapshot);
  void publish_connect_job_state(const VpnConnectJobState &job_state);
  void notify_status_changed();
  std::unique_ptr<State> state_;
};

// Process-global shared instance.  Both the desktop and native VPN handlers
// resolve the controller through this accessor so there is exactly one
// TunnelController in the core process.
TunnelUseCases &tunnel_use_cases();

} // namespace exv::core
