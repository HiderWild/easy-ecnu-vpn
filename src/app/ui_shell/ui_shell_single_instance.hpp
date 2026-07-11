#pragma once

#include <functional>
#include <memory>
#include <string>

namespace exv::ui_shell {

class UiShellSingleInstance {
public:
  virtual ~UiShellSingleInstance() = default;
  virtual bool is_primary() const noexcept = 0;
  virtual void poll_wake_requests(const std::function<void()> &on_wake) = 0;
};

std::unique_ptr<UiShellSingleInstance>
acquire_ui_shell_single_instance(const std::string &state_dir);

} // namespace exv::ui_shell
