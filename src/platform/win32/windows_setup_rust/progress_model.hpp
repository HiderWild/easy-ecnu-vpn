#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

namespace exv::setup {

// Thread-safe target progress in [0,1]; UI lerps toward target.
class ProgressModel {
 public:
  using Listener = std::function<void(double target, const std::wstring &status)>;

  void SetListener(Listener listener);
  void SetStatus(const std::wstring &status);
  void SetTarget(double t);
  void SetStage(double base, double weight, double local01);
  // 声明当前阶段跨度 [base, end]：不改变 target，仅供 UI 的停滞注入读取该阶段满值
  // （卡住时水面以 1%/s 逼近 end，绝不越过，避免无界虚高）。阻塞阶段开始处调用。
  void SetStageSpan(double base, double end);
  double Target() const;
  double StageEnd() const;
  std::wstring Status() const;

 private:
  mutable std::atomic<double> target_{0.0};
  std::atomic<double> stage_end_{0.0};
  std::wstring status_;
  Listener listener_;
};

}  // namespace exv::setup
