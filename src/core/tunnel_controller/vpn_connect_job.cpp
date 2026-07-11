#include "core/tunnel_controller/vpn_connect_job.hpp"

#include <exception>
#include <utility>

namespace exv::core {

VpnConnectJobOwner::~VpnConnectJobOwner() {
  std::jthread active_to_join;
  std::jthread reconcile_to_join;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    destroying_ = true;
    ++shutdown_depth_;
    pending_run_.reset();
    if (reconcile_thread_.joinable()) {
      reconcile_thread_.request_stop();
      reconcile_to_join = std::move(reconcile_thread_);
    }
    if (active_thread_.joinable()) {
      active_thread_.request_stop();
      active_to_join = std::move(active_thread_);
    }
  }
  if (reconcile_to_join.joinable()) {
    reconcile_to_join.join();
  }
  if (active_to_join.joinable()) {
    active_to_join.join();
  }
}

VpnConnectJobState VpnConnectJobOwner::submit_connect(PendingConnectRequest request,
                                                      RunFn run) {
  join_finished();
  StateNotification notification;
  bool should_notify = false;
  VpnConnectJobState result;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (destroying_ || shutdown_depth_ > 0) {
      auto rejected = state_;
      rejected.accepted = false;
      rejected.active = false;
      rejected.coalesced = false;
      rejected.desired_connected = false;
      return rejected;
    }
    intent_.desired = DesiredVpnIntent::Connect;
    intent_.epoch += 1;
    intent_.pending_connect = std::move(request);
    pending_run_ = std::move(run);

    if (state_.active) {
      state_.accepted = true;
      state_.coalesced = true;
      state_.desired_connected = true;
      result = state_;
    } else {
      result = start_job_locked(*pending_run_);
    }
    notification = state_notification_unlocked();
    should_notify = true;
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return result;
}

VpnConnectJobState VpnConnectJobOwner::submit_disconnect(std::string reason) {
  join_finished();
  StateNotification notification;
  VpnConnectJobState result;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    intent_.desired = DesiredVpnIntent::Disconnect;
    intent_.epoch += 1;
    state_.accepted = true;
    state_.desired_connected = false;
    state_.intent_epoch = intent_.epoch;
    pending_run_.reset();

    if (state_.active) {
      state_.cancelling = true;
      state_.user_cancelled = reason == "user_cancelled_connect";
      active_thread_.request_stop();
    }
    result = state_;
    notification = state_notification_unlocked();
  }
  notify_state_changed(std::move(notification));
  return result;
}

VpnConnectJobState VpnConnectJobOwner::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return state_;
}

ConnectProgress VpnConnectJobOwner::connect_progress_snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return connect_progress_.snapshot();
}

bool VpnConnectJobOwner::accepts_update(std::uint64_t epoch) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return epoch != 0 && active_job_epoch_ == epoch && state_.active;
}

bool VpnConnectJobOwner::mark_connect_succeeded(
    std::uint64_t epoch, const PendingConnectRequest &fulfilled_request) {
  StateNotification notification;
  bool should_notify = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (epoch == 0 || active_job_epoch_ != epoch || !state_.active) {
      return false;
    }
    state_.last_error_code.clear();
    state_.last_error_message.clear();
    if (intent_.desired == DesiredVpnIntent::Connect &&
        intent_.epoch > represented_epoch_ &&
        same_pending_connect_request(intent_.pending_connect,
                                     fulfilled_request)) {
      represented_epoch_ = intent_.epoch;
      state_.intent_epoch = intent_.epoch;
      state_.coalesced = false;
      pending_run_.reset();
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return true;
}

bool VpnConnectJobOwner::mark_connect_progress_done(std::string_view key) {
  StateNotification notification;
  bool should_notify = false;
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    updated = mark_connect_progress_locked(0, key, ConnectProgressStepState::Done);
    if (updated) {
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return updated;
}

bool VpnConnectJobOwner::mark_connect_progress_done(std::uint64_t epoch,
                                                    std::string_view key) {
  StateNotification notification;
  bool should_notify = false;
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    updated =
        mark_connect_progress_locked(epoch, key, ConnectProgressStepState::Done);
    if (updated) {
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return updated;
}

bool VpnConnectJobOwner::mark_connect_progress_failed(std::string_view key) {
  StateNotification notification;
  bool should_notify = false;
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    updated =
        mark_connect_progress_locked(0, key, ConnectProgressStepState::Failed);
    if (updated) {
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return updated;
}

bool VpnConnectJobOwner::mark_connect_progress_failed(std::uint64_t epoch,
                                                      std::string_view key) {
  StateNotification notification;
  bool should_notify = false;
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    updated =
        mark_connect_progress_locked(epoch, key,
                                     ConnectProgressStepState::Failed);
    if (updated) {
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return updated;
}

bool VpnConnectJobOwner::mark_connect_progress_skipped(std::string_view key) {
  StateNotification notification;
  bool should_notify = false;
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    updated =
        mark_connect_progress_locked(0, key, ConnectProgressStepState::Skipped);
    if (updated) {
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return updated;
}

bool VpnConnectJobOwner::mark_connect_progress_skipped(std::uint64_t epoch,
                                                       std::string_view key) {
  StateNotification notification;
  bool should_notify = false;
  bool updated = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    updated =
        mark_connect_progress_locked(epoch, key,
                                     ConnectProgressStepState::Skipped);
    if (updated) {
      notification = state_notification_unlocked();
      should_notify = true;
    }
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  return updated;
}

bool VpnConnectJobOwner::request_cancel(std::string reason) {
  StateNotification notification;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!state_.active) {
      return false;
    }
    state_.cancelling = true;
    state_.user_cancelled = reason == "user_cancelled_connect";
    active_thread_.request_stop();
    notification = state_notification_unlocked();
  }
  notify_state_changed(std::move(notification));
  return true;
}

void VpnConnectJobOwner::shutdown(std::string reason) {
  std::jthread thread_to_join;
  std::jthread reconcile_to_join;
  StateNotification stopping_notification;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    ++shutdown_depth_;
    pending_run_.reset();
    intent_.desired = DesiredVpnIntent::Disconnect;
    intent_.epoch += 1;
    state_.accepted = true;
    state_.desired_connected = false;
    state_.intent_epoch = intent_.epoch;
    state_.cancelling = state_.active;
    state_.user_cancelled = reason == "user_cancelled_connect";
    state_.last_error_code.clear();
    state_.last_error_message.clear();
    if (reconcile_thread_.joinable()) {
      reconcile_thread_.request_stop();
      reconcile_to_join = std::move(reconcile_thread_);
    }
    if (active_thread_.joinable()) {
      active_thread_.request_stop();
      thread_to_join = std::move(active_thread_);
    }
    stopping_notification = state_notification_unlocked();
  }
  notify_state_changed(std::move(stopping_notification));

  if (thread_to_join.joinable()) {
    thread_to_join.join();
  }
  if (reconcile_to_join.joinable()) {
    reconcile_to_join.join();
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_run_.reset();
    state_.active = false;
    state_.phase = "idle";
    state_.cancelling = false;
    state_.desired_connected = false;
    connect_progress_.reset();
    refresh_connect_progress_locked();
    if (shutdown_depth_ > 0) {
      --shutdown_depth_;
    }
    stopping_notification = state_notification_unlocked();
  }
  notify_state_changed(std::move(stopping_notification));
}

void VpnConnectJobOwner::reconcile_after_idle() {
  join_finished();
  RunFn run;
  StateNotification notification;
  bool should_notify = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_.active ||
        destroying_ ||
        shutdown_depth_ > 0 ||
        intent_.desired != DesiredVpnIntent::Connect ||
        !pending_run_.has_value() ||
        intent_.epoch <= represented_epoch_) {
      return;
    }
    run = *pending_run_;
    start_job_locked(run);
    notification = state_notification_unlocked();
    should_notify = true;
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
}

void VpnConnectJobOwner::set_state_callback(StateCallback callback) {
  std::lock_guard<std::mutex> lock(mutex_);
  state_callback_ = std::move(callback);
}

void VpnConnectJobOwner::set_before_reconcile_schedule_hook_for_testing(
    std::function<void()> hook) {
  std::lock_guard<std::mutex> lock(mutex_);
  before_reconcile_schedule_hook_for_testing_ = std::move(hook);
}

bool VpnConnectJobOwner::reconcile_thread_joinable_for_testing() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return reconcile_thread_.joinable();
}

VpnConnectJobState VpnConnectJobOwner::start_job_locked(RunFn run) {
  represented_epoch_ = intent_.epoch;
  active_job_epoch_ = intent_.epoch;
  state_ = {};
  connect_progress_.reset();
  connect_progress_.start();
  connect_progress_.mark_done("intent");
  state_.accepted = true;
  state_.active = true;
  state_.phase = "connecting";
  state_.desired_connected = true;
  state_.intent_epoch = intent_.epoch;
  state_.job_id = "connect-" + std::to_string(++next_job_number_);
  refresh_connect_progress_locked();
  const std::uint64_t epoch = intent_.epoch;

  active_thread_ = std::jthread(
      [this, run = std::move(run), epoch](std::stop_token stop) mutable {
        std::string error_code;
        std::string error_message;
        try {
          run(stop, epoch);
        } catch (const std::exception& error) {
          error_code = "job_failed";
          error_message = error.what();
        } catch (...) {
          error_code = "job_failed";
          error_message = "Unhandled VPN connect job failure";
        }
        mark_finished(epoch, std::move(error_code), std::move(error_message));
      });
  return state_;
}

VpnConnectJobOwner::StateNotification
VpnConnectJobOwner::state_notification_unlocked() const {
  return StateNotification{state_, state_callback_};
}

void VpnConnectJobOwner::notify_state_changed(StateNotification notification) {
  if (notification.callback) {
    notification.callback(notification.state);
  }
}

void VpnConnectJobOwner::join_finished() {
  std::jthread thread_to_join;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_thread_.joinable() && !state_.active) {
      thread_to_join = std::move(active_thread_);
    }
  }
  if (thread_to_join.joinable()) {
    thread_to_join.join();
  }
}

bool VpnConnectJobOwner::should_reconcile_after_finish_locked() const {
  return !destroying_ &&
         shutdown_depth_ == 0 &&
         intent_.desired == DesiredVpnIntent::Connect &&
         pending_run_.has_value() &&
         intent_.epoch > represented_epoch_;
}

void VpnConnectJobOwner::schedule_reconcile_after_finish() {
  std::jthread previous_reconcile;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!should_reconcile_after_finish_locked()) {
      return;
    }
    if (reconcile_thread_.joinable()) {
      reconcile_thread_.request_stop();
      previous_reconcile = std::move(reconcile_thread_);
    }
    reconcile_thread_ = std::jthread([this](std::stop_token stop) {
      if (!stop.stop_requested()) {
        reconcile_after_idle();
      }
    });
  }
  if (previous_reconcile.joinable()) {
    previous_reconcile.join();
  }
}

void VpnConnectJobOwner::mark_finished(std::uint64_t epoch,
                                       std::string error_code,
                                       std::string error_message) {
  bool should_reconcile = false;
  std::function<void()> before_reconcile_schedule_hook;
  StateNotification notification;
  bool should_notify = false;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (active_job_epoch_ != epoch) {
      return;
    }
    state_.active = false;
    state_.phase = "idle";
    state_.cancelling = false;
    if (!error_code.empty()) {
      const auto progress = connect_progress_.snapshot();
      if (!progress.active_key.empty()) {
        (void)connect_progress_.mark_failed(progress.active_key);
      }
    }
    if (!state_.user_cancelled) {
      state_.last_error_code = std::move(error_code);
      state_.last_error_message = std::move(error_message);
    }
    refresh_connect_progress_locked();
    should_reconcile = should_reconcile_after_finish_locked();
    if (should_reconcile) {
      before_reconcile_schedule_hook =
          before_reconcile_schedule_hook_for_testing_;
    }
    notification = state_notification_unlocked();
    should_notify = true;
  }
  if (should_notify) {
    notify_state_changed(std::move(notification));
  }
  if (before_reconcile_schedule_hook) {
    before_reconcile_schedule_hook();
  }
  if (should_reconcile) {
    schedule_reconcile_after_finish();
  }
}

void VpnConnectJobOwner::refresh_connect_progress_locked() {
  state_.connect_progress = connect_progress_.snapshot();
}

bool VpnConnectJobOwner::mark_connect_progress_locked(
    std::uint64_t epoch,
    std::string_view key,
    ConnectProgressStepState step_state) {
  if (epoch != 0 && active_job_epoch_ != epoch) {
    return false;
  }

  bool updated = false;
  switch (step_state) {
  case ConnectProgressStepState::Done:
    updated = connect_progress_.mark_done(key);
    break;
  case ConnectProgressStepState::Failed:
    updated = connect_progress_.mark_failed(key);
    break;
  case ConnectProgressStepState::Skipped:
    updated = connect_progress_.mark_skipped(key);
    break;
  case ConnectProgressStepState::Pending:
  case ConnectProgressStepState::Active:
    updated = false;
    break;
  }
  if (updated) {
    refresh_connect_progress_locked();
  }
  return updated;
}

} // namespace exv::core
