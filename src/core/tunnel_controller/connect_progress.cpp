#include "core/tunnel_controller/connect_progress_json.hpp"

namespace exv::core {

const char *connect_progress_state_wire_name(
    ConnectProgressStepState state) noexcept {
  switch (state) {
  case ConnectProgressStepState::Pending:
    return "pending";
  case ConnectProgressStepState::Active:
    return "active";
  case ConnectProgressStepState::Done:
    return "done";
  case ConnectProgressStepState::Failed:
    return "failed";
  case ConnectProgressStepState::Skipped:
    return "skipped";
  }
  return "pending";
}

ConnectProgressTracker::ConnectProgressTracker() { reset(); }

void ConnectProgressTracker::reset() {
  started_ = false;
  failed_key_.clear();
  steps_ = default_connect_progress_steps();
}

void ConnectProgressTracker::start() { started_ = true; }

bool ConnectProgressTracker::mark_done(std::string_view key) {
  return set_state(key, ConnectProgressStepState::Done);
}

bool ConnectProgressTracker::mark_failed(std::string_view key) {
  return set_state(key, ConnectProgressStepState::Failed);
}

bool ConnectProgressTracker::mark_skipped(std::string_view key) {
  return set_state(key, ConnectProgressStepState::Skipped);
}

ConnectProgress ConnectProgressTracker::snapshot() const {
  ConnectProgress progress;
  progress.steps = steps_;
  progress.active_key.clear();

  if (!failed_key_.empty()) {
    progress.active_key = failed_key_;
    return progress;
  }

  if (!started_) {
    return progress;
  }

  for (auto &step : progress.steps) {
    if (step.state == ConnectProgressStepState::Pending) {
      step.state = ConnectProgressStepState::Active;
      progress.active_key = step.key;
      break;
    }
  }
  return progress;
}

bool ConnectProgressTracker::set_state(std::string_view key,
                                       ConnectProgressStepState state) {
  for (auto &step : steps_) {
    if (std::string_view(step.key) != key) {
      continue;
    }
    step.state = state;
    if (state == ConnectProgressStepState::Failed) {
      started_ = true;
      failed_key_ = step.key;
    } else if (failed_key_ == step.key) {
      failed_key_.clear();
    }
    return true;
  }
  return false;
}

nlohmann::json connect_progress_to_json(const ConnectProgress &progress) {
  nlohmann::json steps = nlohmann::json::array();
  for (const auto &step : progress.steps) {
    steps.push_back({
        {"key", step.key},
        {"label", step.label},
        {"description", step.description},
        {"state", connect_progress_state_wire_name(step.state)},
        {"priority", step.priority},
        {"visual", step.visual},
    });
  }

  return nlohmann::json{
      {"active_key", progress.active_key},
      {"steps", std::move(steps)},
  };
}

} // namespace exv::core
