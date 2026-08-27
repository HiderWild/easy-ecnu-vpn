#include "windows_setup_rust/progress_model.hpp"

#include <algorithm>
#include <mutex>

namespace exv::setup {
namespace {
std::mutex g_status_mu;
}

void ProgressModel::SetListener(Listener listener) {
  listener_ = std::move(listener);
}

void ProgressModel::SetStatus(const std::wstring &status) {
  {
    std::lock_guard lock(g_status_mu);
    status_ = status;
  }
  if (listener_) {
    listener_(Target(), status);
  }
}

void ProgressModel::SetTarget(double t) {
  target_.store(std::clamp(t, 0.0, 1.0));
  if (listener_) {
    listener_(Target(), Status());
  }
}

void ProgressModel::SetStage(double base, double weight, double local01) {
  SetTarget(base + weight * std::clamp(local01, 0.0, 1.0));
}

void ProgressModel::SetStageSpan(double base, double end) {
  stage_end_.store(std::clamp(end, 0.0, 1.0));
  (void)base;  // begin 仅作语义占位；UI 以最后一次真实进度作为蠕动起点
}

double ProgressModel::Target() const {
  return target_.load();
}

double ProgressModel::StageEnd() const {
  return stage_end_.load();
}

std::wstring ProgressModel::Status() const {
  std::lock_guard lock(g_status_mu);
  return status_;
}

}  // namespace exv::setup
