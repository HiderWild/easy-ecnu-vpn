#include "core/use_cases/tunnel_use_cases.hpp"

#include "core/connection/connection_attempt.hpp"
#include "core/connection/tunnel_resource_lease.hpp"
#include "core/tunnel_controller/tunnel_controller.hpp"
#include "core/tunnel_controller/tunnel_controller_active.hpp"
#include "core/use_cases/connection_runtime_coordinator.hpp"
#include "helper/common/helper_client.hpp"
#include "helper/common/helper_connector.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/helper_delegating_network_ops.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_paths.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace exv::core {

namespace {

bool is_terminal_runtime_snapshot(const TunnelStatusSnapshot &snapshot) {
  if (snapshot.phase == TunnelPhase::Failed) {
    return true;
  }
  if (snapshot.phase != TunnelPhase::Idle) {
    return false;
  }
  return !snapshot.session_active && !snapshot.network_ready &&
         !snapshot.core_lease_active;
}

bool is_recoverable_same_process_startup_snapshot(
    const TunnelStatusSnapshot &snapshot) {
  const bool recoverable_phase =
      snapshot.phase == TunnelPhase::PreparingHelper ||
      snapshot.phase == TunnelPhase::Reconnecting;
  if (!recoverable_phase) {
    return false;
  }
  return snapshot.helper_status == "unavailable" || snapshot.session_active ||
         snapshot.core_lease_active;
}

bool is_connected_runtime_snapshot(const TunnelStatusSnapshot &snapshot) {
  return snapshot.phase == TunnelPhase::Connected && snapshot.network_ready;
}

bool is_connecting_or_recovering_runtime_snapshot(
    const TunnelStatusSnapshot &snapshot) {
  switch (snapshot.phase) {
  case TunnelPhase::PreparingHelper:
  case TunnelPhase::Authenticating:
  case TunnelPhase::ConnectingCstp:
  case TunnelPhase::ApplyingNetworkConfig:
  case TunnelPhase::OpeningPacketDevice:
  case TunnelPhase::Reconnecting:
    return true;
  case TunnelPhase::Idle:
  case TunnelPhase::Connected:
  case TunnelPhase::Disconnecting:
  case TunnelPhase::CleaningUp:
  case TunnelPhase::Failed:
    return false;
  }
  return false;
}

bool can_reconcile_published_terminal_runtime(
    const TunnelStatusSnapshot &snapshot, bool attempt_present) {
  if (!is_terminal_runtime_snapshot(snapshot)) {
    return false;
  }
  if (snapshot.phase == TunnelPhase::Idle && !attempt_present) {
    return false;
  }
  return true;
}

bool can_reconcile_same_process_attempt(const TunnelStatusSnapshot &snapshot) {
  return is_terminal_runtime_snapshot(snapshot) ||
         is_recoverable_same_process_startup_snapshot(snapshot);
}

std::string terminal_reconcile_phase_name(const TunnelStatusSnapshot &snapshot) {
  return tunnel_phase_wire_name(snapshot.phase);
}

std::string bool_field(bool value) { return value ? "true" : "false"; }

std::string failure_code_field(const nlohmann::json &failure) {
  if (!failure.is_object()) {
    return {};
  }
  const auto code = failure.value("code", std::string());
  if (!code.empty()) {
    return code;
  }
  return failure.value("error_code", std::string());
}

std::vector<std::pair<std::string, std::string>>
runtime_reconcile_fields(const TunnelStatusSnapshot &snapshot,
                         const std::string &reason, bool attempt_present,
                         bool lease_present) {
  return {{"reason", reason},
          {"phase", terminal_reconcile_phase_name(snapshot)},
          {"helper_status", snapshot.helper_status},
          {"session_active", bool_field(snapshot.session_active)},
          {"network_ready", bool_field(snapshot.network_ready)},
          {"core_lease_active", bool_field(snapshot.core_lease_active)},
          {"attempt_present", bool_field(attempt_present)},
          {"lease_present", bool_field(lease_present)}};
}

} // namespace

// Holder of the shared tunnel runtime.  Relocated verbatim from the former
// core/app_api/desktop_tunnel_host.cpp file-local TunnelControllerHolder so
// that ownership now lives in the use-case layer.
struct TunnelUseCases::State {
  std::unique_ptr<exv::helper::HelperConnector> connector;
  std::shared_ptr<exv::helper::HelperClient> client;
  std::shared_ptr<exv::platform::HelperDelegatingPlatformNetworkOps> net_ops;
  std::shared_ptr<exv::core::TunnelController> controller;
  bool init_attempted = false;
  std::string init_error;
  std::chrono::steady_clock::time_point last_failure_time;
  static constexpr auto kRetryCooldown = std::chrono::seconds(30);

  // Active tunnel resource lease, held for the whole connected/reconnecting
  // runtime so competing processes cannot reset the shared Wintun/controller
  // resources out from under this process.
  mutable std::mutex runtime_mutex;
  std::string active_tunnel_lease_id;
  std::string active_connection_attempt_config_dir;
  std::string active_connection_attempt_id;
  ConnectionRuntimeCoordinator runtime_coordinator;

  // Desktop connect-error state (guarded by connect_error_mutex).
  std::mutex connect_error_mutex;
  std::optional<nlohmann::json> connect_error;

  // Desktop connect-job owner.  VpnConnectJobOwner synchronizes its own state.
  // Declared after connect_error so that ~State joins the connect-job thread
  // before the error state is destroyed.
  std::mutex connect_jobs_mutex;
  VpnConnectJobOwner connect_jobs;

  mutable std::mutex status_observer_mutex;
  std::map<StatusObserverId, StatusObserver> status_observers;
  StatusObserverId next_status_observer_id = 0;
  std::optional<TunnelStatusSnapshot> latest_status;

  mutable std::mutex connect_job_observer_mutex;
  std::map<ConnectJobObserverId, ConnectJobObserver> connect_job_observers;
  ConnectJobObserverId next_connect_job_observer_id = 0;
  VpnConnectJobState latest_connect_job;
};

TunnelUseCases::TunnelUseCases() : state_(std::make_unique<State>()) {
  state_->latest_connect_job = state_->connect_jobs.snapshot();
  state_->connect_jobs.set_state_callback(
      [this](const VpnConnectJobState &job_state) {
        publish_connect_job_state(job_state);
      });
}

TunnelUseCases::~TunnelUseCases() {
  if (state_) {
    state_->connect_jobs.set_state_callback({});
  }
}

std::string TunnelUseCases::helper_binary_next_to_exv() {
  std::filesystem::path exv_path(platform::get_executable_path());
#ifdef _WIN32
  return (exv_path.parent_path() / "exv-helper.exe").string();
#else
  return (exv_path.parent_path() / "exv-helper").string();
#endif
}

std::shared_ptr<exv::core::TunnelController>
TunnelUseCases::ensure_controller(const std::string &endpoint_override) {
  auto &h = *state_;
  if (h.controller) {
    exv::core::set_tunnel_controller_active(true);
    return h.controller;
  }

  const auto now = std::chrono::steady_clock::now();
  if (h.last_failure_time != std::chrono::steady_clock::time_point{}) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - h.last_failure_time);
    if (elapsed < State::kRetryCooldown) {
      exv::observability::LogFacade::event(
          "WARN", "tunnel", "tunnel_controller.init.cooldown_blocked",
          "TunnelController initialization is blocked by retry cooldown",
          {{"seconds_remaining",
            std::to_string((State::kRetryCooldown - elapsed).count())}});
      return nullptr;
    }
  }

  h.init_attempted = true;
  try {
    h.connector = exv::helper::HelperConnector::create();
    exv::helper::HelperConnectorConfig cc;
    cc.mode = exv::helper::ConnectorMode::Transient;
    if (!endpoint_override.empty()) {
      cc.pipe_endpoint = endpoint_override;
    } else {
      cc.helper_executable_path = helper_binary_next_to_exv();
    }
    h.client = h.connector->connect(cc);
    if (!h.client) {
      h.init_error = "Failed to connect to helper daemon";
      exv::observability::LogFacade::event(
          "WARN", "tunnel", "tunnel_controller.init.helper_connect_failed",
          "Failed to connect helper client while initializing TunnelController",
          {{"endpoint", cc.pipe_endpoint.empty() ? std::string("default")
                                                 : cc.pipe_endpoint}});
      h.last_failure_time = now;
      return nullptr;
    }
    h.net_ops =
        std::make_shared<exv::platform::HelperDelegatingPlatformNetworkOps>(
            h.client.get());
    h.controller =
        std::make_shared<exv::core::TunnelController>(h.client, h.net_ops);
    const auto identity = h.runtime_coordinator.begin_runtime(
        endpoint_override.empty() ? "ensure_controller_default"
                                  : "ensure_controller_endpoint");
    h.controller->set_runtime_identity(identity.runtime_epoch,
                                       identity.controller_id);
    h.controller->set_status_callback(
        [this](const exv::core::TunnelStatusSnapshot &snapshot) {
          publish_status_from_controller(snapshot.controller_id, snapshot);
        });
    h.controller->set_recovery_callback(
        [this](const exv::core::TunnelRecoveryRequest &request) {
          request_recovery(request);
        });
    exv::core::set_tunnel_controller_active(true);
    publish_status(h.controller->status());
    return h.controller;
  } catch (const std::exception &e) {
    h.init_error = e.what();
    exv::observability::LogFacade::event(
        "ERROR", "tunnel", "tunnel_controller.init.exception",
        "TunnelController initialization threw an exception",
        {{"message", e.what()}});
    h.last_failure_time = now;
    return nullptr;
  }
}

std::shared_ptr<exv::core::TunnelController>
TunnelUseCases::controller_if_exists() const {
  return state_->controller;
}

std::shared_ptr<exv::helper::HelperClient>
TunnelUseCases::current_helper_client() const {
  return state_->client;
}

TunnelUseCases::StatusObserverId
TunnelUseCases::add_status_observer(StatusObserver observer) {
  if (!observer) {
    return 0;
  }
  std::lock_guard<std::mutex> lock(state_->status_observer_mutex);
  const auto id = ++state_->next_status_observer_id;
  state_->status_observers.emplace(id, std::move(observer));
  return id;
}

void TunnelUseCases::remove_status_observer(StatusObserverId id) {
  std::lock_guard<std::mutex> lock(state_->status_observer_mutex);
  state_->status_observers.erase(id);
}

TunnelUseCases::ConnectJobObserverId
TunnelUseCases::add_connect_job_observer(ConnectJobObserver observer) {
  if (!observer) {
    return 0;
  }
  std::lock_guard<std::mutex> lock(state_->connect_job_observer_mutex);
  const auto id = ++state_->next_connect_job_observer_id;
  state_->connect_job_observers.emplace(id, std::move(observer));
  return id;
}

void TunnelUseCases::remove_connect_job_observer(ConnectJobObserverId id) {
  std::lock_guard<std::mutex> lock(state_->connect_job_observer_mutex);
  state_->connect_job_observers.erase(id);
}

std::optional<TunnelStatusSnapshot> TunnelUseCases::latest_status() const {
  std::lock_guard<std::mutex> lock(state_->status_observer_mutex);
  return state_->latest_status;
}

VpnConnectJobState TunnelUseCases::latest_connect_job() const {
  std::lock_guard<std::mutex> lock(state_->connect_job_observer_mutex);
  return state_->latest_connect_job;
}

void TunnelUseCases::publish_status(const TunnelStatusSnapshot &snapshot) {
  std::vector<StatusObserver> observers;
  {
    std::lock_guard<std::mutex> lock(state_->status_observer_mutex);
    state_->latest_status = snapshot;
    observers.reserve(state_->status_observers.size());
    for (const auto &[id, observer] : state_->status_observers) {
      (void)id;
      observers.push_back(observer);
    }
  }
  if (is_connected_runtime_snapshot(snapshot)) {
    if (connect_error().has_value()) {
      exv::observability::LogFacade::event(
          "INFO", "tunnel", "desktop.connect_error.cleared_connected",
          "Cleared stored desktop connect error after controller reached Connected",
          {{"phase", tunnel_phase_wire_name(snapshot.phase)},
           {"network_ready", bool_field(snapshot.network_ready)}});
    }
    clear_connect_error();
  }
  reconcile_terminal_runtime(
      snapshot, "status_" + terminal_reconcile_phase_name(snapshot));
  for (const auto &observer : observers) {
    if (observer) {
      observer(snapshot);
    }
  }
}

void TunnelUseCases::publish_status_from_controller(
    std::uint64_t controller_id, const TunnelStatusSnapshot &snapshot) {
  if (!state_->runtime_coordinator.accepts_status(snapshot)) {
    const auto current = state_->runtime_coordinator.current_identity();
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "connection.runtime.stale_status_ignored",
        "Ignored stale TunnelController status",
        {{"runtime_epoch", std::to_string(snapshot.runtime_epoch)},
         {"controller_id", std::to_string(controller_id)},
         {"current_runtime_epoch", std::to_string(current.runtime_epoch)},
         {"current_controller_id", std::to_string(current.controller_id)},
         {"phase", tunnel_phase_wire_name(snapshot.phase)}});
    return;
  }
  publish_status(snapshot);
}

void TunnelUseCases::publish_connect_job_state(
    const VpnConnectJobState &job_state) {
  std::vector<ConnectJobObserver> observers;
  {
    std::lock_guard<std::mutex> lock(state_->connect_job_observer_mutex);
    state_->latest_connect_job = job_state;
    observers.reserve(state_->connect_job_observers.size());
    for (const auto &[id, observer] : state_->connect_job_observers) {
      (void)id;
      observers.push_back(observer);
    }
  }
  for (const auto &observer : observers) {
    if (observer) {
      observer(job_state);
    }
  }
}

void TunnelUseCases::notify_status_changed() {
  publish_connect_job_state(state_->connect_jobs.snapshot());
}

std::mutex &TunnelUseCases::connect_jobs_mutex() {
  return state_->connect_jobs_mutex;
}

VpnConnectJobOwner &TunnelUseCases::connect_jobs() {
  return state_->connect_jobs;
}

std::optional<nlohmann::json> TunnelUseCases::connect_error() const {
  std::lock_guard<std::mutex> lock(state_->connect_error_mutex);
  return state_->connect_error;
}

void TunnelUseCases::set_connect_error(nlohmann::json failure) {
  {
    std::lock_guard<std::mutex> status_lock(state_->status_observer_mutex);
    if (state_->latest_status.has_value() &&
        is_connected_runtime_snapshot(*state_->latest_status)) {
      exv::observability::LogFacade::event(
          "INFO", "tunnel", "desktop.connect_error.suppressed_connected",
          "Suppressed late desktop connect error because the controller is already Connected",
          {{"code", failure_code_field(failure)},
           {"phase", tunnel_phase_wire_name(state_->latest_status->phase)}});
      return;
    }
  }
  {
    std::lock_guard<std::mutex> lock(state_->connect_error_mutex);
    state_->connect_error = std::move(failure);
  }
  notify_status_changed();
}

void TunnelUseCases::set_connect_error(std::uint64_t epoch,
                                       nlohmann::json failure) {
  if (!state_->connect_jobs.accepts_update(epoch)) {
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "connection.runtime.stale_error_ignored",
        "Ignored stale desktop connect error from a retired connect job",
        {{"runtime_epoch", std::to_string(epoch)},
         {"code", failure_code_field(failure)}});
    return;
  }
  set_connect_error(std::move(failure));
}

void TunnelUseCases::clear_connect_error() {
  bool changed = false;
  {
    std::lock_guard<std::mutex> lock(state_->connect_error_mutex);
    changed = state_->connect_error.has_value();
    state_->connect_error.reset();
  }
  if (changed) {
    notify_status_changed();
  }
}

void TunnelUseCases::clear_connect_error(std::uint64_t epoch) {
  if (!state_->connect_jobs.accepts_update(epoch)) {
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "connection.runtime.stale_error_ignored",
        "Ignored stale desktop connect error clear from a retired connect job",
        {{"runtime_epoch", std::to_string(epoch)}});
    return;
  }
  clear_connect_error();
}

void TunnelUseCases::shutdown_connect_jobs(const std::string &reason) {
  state_->connect_jobs.shutdown(reason);
}

bool TunnelUseCases::acquire_active_tunnel_lease(
    const std::string &owner, const std::string &profile_id,
    std::string *error_code, std::string *error_message) {
  std::lock_guard<std::mutex> lock(state_->runtime_mutex);
  if (!state_->active_tunnel_lease_id.empty()) {
    exv::observability::LogFacade::warn(
        "active_tunnel_lease.acquire.blocked same_process=true owner=" +
        owner + " profile_id=" + profile_id);
    if (error_code) {
      *error_code =
          exv::connection::tunnel_resource_lease::kTunnelResourceActiveCode;
    }
    if (error_message) {
      *error_message = "Another EXV tunnel is already active.";
    }
    return false;
  }

  exv::connection::tunnel_resource_lease::AcquireOptions options;
  options.config_dir = platform::get_config_dir();
  options.owner_pid = exv::connection_attempt::current_process_id();
  options.owner = owner;
  options.profile_id = profile_id;

  auto acquired =
      exv::connection::tunnel_resource_lease::try_acquire(options);
  if (!acquired.acquired) {
    exv::observability::LogFacade::warn(
        "active_tunnel_lease.acquire.blocked code=" + acquired.code +
        " owner=" + owner + " profile_id=" + profile_id +
        " active_owner_pid=" +
        std::to_string(acquired.record.owner_pid));
    if (error_code) {
      *error_code = acquired.code;
    }
    if (error_message) {
      *error_message = acquired.message;
    }
    return false;
  }

  state_->active_tunnel_lease_id = acquired.record.lease_id;
  exv::observability::LogFacade::info(
      "active_tunnel_lease.acquire.completed lease_id=" +
      acquired.record.lease_id + " owner=" + owner +
      " profile_id=" + profile_id +
      " stale_replaced=" + (acquired.stale_replaced ? "true" : "false"));
  return true;
}

void TunnelUseCases::release_active_tunnel_lease() {
  std::string lease_id;
  {
    std::lock_guard<std::mutex> lock(state_->runtime_mutex);
    lease_id.swap(state_->active_tunnel_lease_id);
  }
  if (!lease_id.empty()) {
    exv::observability::LogFacade::info(
        "active_tunnel_lease.release.starting lease_id=" + lease_id);
    (void)exv::connection::tunnel_resource_lease::release_if_owner(
        platform::get_config_dir(), lease_id);
    exv::observability::LogFacade::info(
        "active_tunnel_lease.release.completed lease_id=" + lease_id);
  }
}

std::string TunnelUseCases::active_tunnel_lease_id() const {
  std::lock_guard<std::mutex> lock(state_->runtime_mutex);
  return state_->active_tunnel_lease_id;
}

void TunnelUseCases::track_active_connection_attempt(
    const std::string &config_dir, const std::string &attempt_id) {
  if (config_dir.empty() || attempt_id.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock(state_->runtime_mutex);
  state_->active_connection_attempt_config_dir = config_dir;
  state_->active_connection_attempt_id = attempt_id;
}

bool TunnelUseCases::reconcile_terminal_runtime(
    const TunnelStatusSnapshot &snapshot, const std::string &reason) {
  bool attempt_present = false;
  bool lease_present = false;
  {
    std::lock_guard<std::mutex> lock(state_->runtime_mutex);
    attempt_present = !state_->active_connection_attempt_id.empty();
    lease_present = !state_->active_tunnel_lease_id.empty();
  }

  if (!can_reconcile_published_terminal_runtime(snapshot, attempt_present)) {
    if (attempt_present || lease_present) {
      exv::observability::LogFacade::event(
          "INFO", "tunnel", "tunnel.runtime_reconcile.skipped",
          "Skipped terminal runtime reconciliation because status is not "
          "releasable",
          runtime_reconcile_fields(snapshot, reason, attempt_present,
                                   lease_present));
    }
    return false;
  }

  exv::observability::LogFacade::event(
      "INFO", "tunnel", "tunnel.runtime_reconcile.started",
      "Reconciling terminal tunnel runtime guards",
      runtime_reconcile_fields(snapshot, reason, attempt_present,
                               lease_present));

  std::string attempt_config_dir;
  std::string attempt_id;
  std::string lease_id;
  {
    std::lock_guard<std::mutex> lock(state_->runtime_mutex);
    attempt_config_dir.swap(state_->active_connection_attempt_config_dir);
    attempt_id.swap(state_->active_connection_attempt_id);
    lease_id.swap(state_->active_tunnel_lease_id);
  }

  bool reconciled = false;
  if (!attempt_config_dir.empty() && !attempt_id.empty()) {
    reconciled = exv::connection_attempt::mark_terminal_if_current(
                     attempt_config_dir, attempt_id, reason) ||
                 reconciled;
  }
  if (!lease_id.empty()) {
    (void)exv::connection::tunnel_resource_lease::release_if_owner(
        platform::get_config_dir(), lease_id);
    reconciled = true;
  }
  auto fields =
      runtime_reconcile_fields(snapshot, reason, !attempt_id.empty(),
                               !lease_id.empty());
  fields.emplace_back("reconciled", bool_field(reconciled));
  exv::observability::LogFacade::event(
      "INFO", "tunnel", "tunnel.runtime_reconcile.completed",
      "Completed terminal tunnel runtime guard reconciliation", fields);
  return reconciled;
}

bool TunnelUseCases::reconcile_terminal_runtime(const std::string &reason) {
  if (auto controller = state_->controller) {
    return reconcile_terminal_runtime(controller->status(), reason);
  }

  const auto snapshot = latest_status();
  if (!snapshot.has_value()) {
    return false;
  }
  return reconcile_terminal_runtime(*snapshot, reason);
}

bool TunnelUseCases::reconcile_terminal_connection_attempt(
    const TunnelStatusSnapshot &snapshot, const std::string &config_dir,
    const std::string &attempt_id, int owner_pid, const std::string &reason) {
  bool lease_present = false;
  {
    std::lock_guard<std::mutex> lock(state_->runtime_mutex);
    lease_present = !state_->active_tunnel_lease_id.empty();
  }

  if (config_dir.empty() || attempt_id.empty()) {
    return false;
  }
  if (owner_pid != exv::connection_attempt::current_process_id()) {
    auto fields =
        runtime_reconcile_fields(snapshot, reason, true, lease_present);
    fields.emplace_back("owner_pid", std::to_string(owner_pid));
    fields.emplace_back(
        "current_pid",
        std::to_string(exv::connection_attempt::current_process_id()));
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "tunnel.runtime_reconcile.skipped",
        "Skipped terminal runtime reconciliation for a non-local owner",
        fields);
    return false;
  }
  if (!can_reconcile_same_process_attempt(snapshot)) {
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "tunnel.runtime_reconcile.skipped",
        "Skipped terminal runtime reconciliation because status is not "
        "releasable",
        runtime_reconcile_fields(snapshot, reason, true, lease_present));
    return false;
  }
  const bool nonterminal_runtime = !is_terminal_runtime_snapshot(snapshot);

  exv::observability::LogFacade::event(
      "INFO", "tunnel", "tunnel.runtime_reconcile.started",
      "Reconciling terminal same-process connection attempt",
      runtime_reconcile_fields(snapshot, reason, true, lease_present));

  std::string lease_id;
  {
    std::lock_guard<std::mutex> lock(state_->runtime_mutex);
    if (state_->active_connection_attempt_id == attempt_id) {
      state_->active_connection_attempt_config_dir.clear();
      state_->active_connection_attempt_id.clear();
    }
    lease_id.swap(state_->active_tunnel_lease_id);
  }

  if (nonterminal_runtime) {
    auto fields = runtime_reconcile_fields(snapshot, reason, true,
                                           !lease_id.empty());
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "tunnel.runtime_reconcile.controller_reset",
        "Resetting live controller before same-process non-terminal retry",
        fields);
    reset_controller(false);
  }

  bool reconciled = exv::connection_attempt::mark_terminal_if_current(
      config_dir, attempt_id, reason);
  if (!lease_id.empty()) {
    (void)exv::connection::tunnel_resource_lease::release_if_owner(
        platform::get_config_dir(), lease_id);
    reconciled = true;
  }
  auto fields = runtime_reconcile_fields(snapshot, reason, true,
                                         !lease_id.empty());
  fields.emplace_back("reconciled", bool_field(reconciled));
  exv::observability::LogFacade::event(
      "INFO", "tunnel", "tunnel.runtime_reconcile.completed",
      "Completed terminal same-process connection attempt reconciliation",
      fields);
  return reconciled;
}

bool TunnelUseCases::reconcile_terminal_connection_attempt(
    const std::string &config_dir, const std::string &attempt_id, int owner_pid,
    const std::string &reason) {
  if (auto controller = state_->controller) {
    return reconcile_terminal_connection_attempt(
        controller->status(), config_dir, attempt_id, owner_pid, reason);
  }

  const auto snapshot = latest_status();
  if (!snapshot.has_value()) {
    return false;
  }
  return reconcile_terminal_connection_attempt(*snapshot, config_dir, attempt_id,
                                               owner_pid, reason);
}

void TunnelUseCases::request_recovery(const TunnelRecoveryRequest &request) {
  const auto current = state_->runtime_coordinator.current_identity();
  if (request.runtime_epoch != current.runtime_epoch ||
      request.controller_id != current.controller_id) {
    exv::observability::LogFacade::event(
        "INFO", "tunnel", "connection.runtime.stale_status_ignored",
        "Ignored stale recovery request",
        {{"runtime_epoch", std::to_string(request.runtime_epoch)},
         {"controller_id", std::to_string(request.controller_id)},
         {"current_runtime_epoch", std::to_string(current.runtime_epoch)},
         {"current_controller_id", std::to_string(current.controller_id)},
         {"reason", request.reason}});
    return;
  }

  exv::observability::LogFacade::event(
      "WARN", "tunnel", "connection.runtime.recovery_requested",
      "Current tunnel controller requested coordinator recovery",
      {{"runtime_epoch", std::to_string(request.runtime_epoch)},
       {"controller_id", std::to_string(request.controller_id)},
       {"reason", request.reason},
       {"error_code", request.error.code}});

  state_->runtime_coordinator.retire_controller(request.controller_id,
                                                "recovery_" + request.reason);

  std::string attempt_config_dir;
  std::string attempt_id;
  std::string lease_id;
  {
    std::lock_guard<std::mutex> lock(state_->runtime_mutex);
    attempt_config_dir.swap(state_->active_connection_attempt_config_dir);
    attempt_id.swap(state_->active_connection_attempt_id);
    lease_id.swap(state_->active_tunnel_lease_id);
  }

  bool attempt_released = false;
  if (!attempt_config_dir.empty() && !attempt_id.empty()) {
    attempt_released = exv::connection_attempt::mark_terminal_if_current(
        attempt_config_dir, attempt_id, "recovery_" + request.reason);
  }

  bool lease_released = false;
  if (!lease_id.empty()) {
    lease_released = exv::connection::tunnel_resource_lease::release_if_owner(
        platform::get_config_dir(), lease_id);
  }

  exv::observability::LogFacade::event(
      "INFO", "tunnel", "connection.runtime.reconcile_completed",
      "Released runtime guards after coordinator recovery request",
      {{"runtime_epoch", std::to_string(request.runtime_epoch)},
       {"controller_id", std::to_string(request.controller_id)},
       {"reason", request.reason},
       {"attempt_released", bool_field(attempt_released)},
       {"lease_released", bool_field(lease_released)}});
  clear_connect_error();
}

bool TunnelUseCases::current_runtime_is_connected() const {
  const auto status = latest_status();
  if (!status.has_value() || !is_connected_runtime_snapshot(*status)) {
    return false;
  }
  return state_->runtime_coordinator.accepts_status(*status);
}

bool TunnelUseCases::current_runtime_is_connecting_or_recovering() const {
  const auto job = latest_connect_job();
  if (job.active && job.desired_connected) {
    return true;
  }
  const auto status = latest_status();
  if (!status.has_value() ||
      !is_connecting_or_recovering_runtime_snapshot(*status)) {
    return false;
  }
  return state_->runtime_coordinator.accepts_status(*status);
}

void TunnelUseCases::reset_controller(bool release_active_lease) {
  auto &h = *state_;
  const auto identity = h.runtime_coordinator.current_identity();
  h.runtime_coordinator.retire_controller(identity.controller_id,
                                          "reset_controller");
  h.controller.reset();
  h.client.reset();
  h.net_ops.reset();
  h.connector.reset();
  h.init_attempted = false;
  h.init_error.clear();
  h.last_failure_time = std::chrono::steady_clock::time_point{};
  exv::core::set_tunnel_controller_active(false);
  if (release_active_lease) {
    release_active_tunnel_lease();
  }
  publish_status(TunnelStatusSnapshot{});
}

std::string TunnelUseCases::controller_init_error() const {
  return state_->init_error;
}

TunnelUseCases &tunnel_use_cases() {
  static TunnelUseCases instance;
  return instance;
}

} // namespace exv::core
