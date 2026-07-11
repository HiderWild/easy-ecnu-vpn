#pragma once

#include "core/tunnel_controller/connect_progress.hpp"
#include "core/tunnel_controller/connect_intent.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace exv::core {

struct VpnConnectJobState {
  std::string job_id;
  std::string phase;
  bool accepted = false;
  bool active = false;
  bool cancelling = false;
  bool user_cancelled = false;
  bool coalesced = false;
  bool desired_connected = false;
  std::uint64_t intent_epoch = 0;
  std::string last_error_code;
  std::string last_error_message;
  ConnectProgress connect_progress;
};

class VpnConnectJobOwner {
public:
  using RunFn = std::function<void(std::stop_token, std::uint64_t)>;
  using StateCallback = std::function<void(const VpnConnectJobState&)>;

  VpnConnectJobOwner() = default;
  ~VpnConnectJobOwner();

  VpnConnectJobOwner(const VpnConnectJobOwner&) = delete;
  VpnConnectJobOwner& operator=(const VpnConnectJobOwner&) = delete;

  VpnConnectJobState submit_connect(PendingConnectRequest request, RunFn run);
  VpnConnectJobState submit_disconnect(std::string reason);
  VpnConnectJobState snapshot() const;
  ConnectProgress connect_progress_snapshot() const;
  bool accepts_update(std::uint64_t epoch) const;
  bool mark_connect_succeeded(std::uint64_t epoch,
                              const PendingConnectRequest &fulfilled_request);
  bool mark_connect_progress_done(std::string_view key);
  bool mark_connect_progress_done(std::uint64_t epoch, std::string_view key);
  bool mark_connect_progress_failed(std::string_view key);
  bool mark_connect_progress_failed(std::uint64_t epoch, std::string_view key);
  bool mark_connect_progress_skipped(std::string_view key);
  bool mark_connect_progress_skipped(std::uint64_t epoch, std::string_view key);
  bool request_cancel(std::string reason);
  void shutdown(std::string reason);
  void reconcile_after_idle();
  void set_state_callback(StateCallback callback);

private:
  friend class VpnConnectJobOwnerTestAccess;

  struct StateNotification {
    VpnConnectJobState state;
    StateCallback callback;
  };

  void set_before_reconcile_schedule_hook_for_testing(std::function<void()> hook);
  bool reconcile_thread_joinable_for_testing() const;
  VpnConnectJobState start_job_locked(RunFn run);
  StateNotification state_notification_unlocked() const;
  static void notify_state_changed(StateNotification notification);
  void join_finished();
  void schedule_reconcile_after_finish();
  bool should_reconcile_after_finish_locked() const;
  void mark_finished(std::uint64_t epoch,
                     std::string error_code,
                     std::string error_message);
  void refresh_connect_progress_locked();
  bool mark_connect_progress_locked(std::uint64_t epoch,
                                    std::string_view key,
                                    ConnectProgressStepState step_state);

  mutable std::mutex mutex_;
  VpnWorkflowIntent intent_;
  VpnConnectJobState state_;
  ConnectProgressTracker connect_progress_;
  std::optional<RunFn> pending_run_;
  std::jthread active_thread_;
  std::jthread reconcile_thread_;
  StateCallback state_callback_;
  std::function<void()> before_reconcile_schedule_hook_for_testing_;
  std::uint64_t next_job_number_ = 0;
  std::uint64_t represented_epoch_ = 0;
  std::uint64_t active_job_epoch_ = 0;
  std::uint32_t shutdown_depth_ = 0;
  bool destroying_ = false;
};

class VpnConnectJobOwnerTestAccess {
public:
  static void set_before_reconcile_schedule_hook(VpnConnectJobOwner &owner,
                                                 std::function<void()> hook) {
    owner.set_before_reconcile_schedule_hook_for_testing(std::move(hook));
  }

  static bool reconcile_thread_joinable(const VpnConnectJobOwner &owner) {
    return owner.reconcile_thread_joinable_for_testing();
  }
};

} // namespace exv::core
