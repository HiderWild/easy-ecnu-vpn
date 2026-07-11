#include "app/ui_shell/ui_shell_single_instance.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <memory>
#include <sstream>
#include <string>

namespace exv::ui_shell {
namespace {

std::wstring single_instance_name(const std::string &state_dir) {
  unsigned long long hash = 1469598103934665603ull;
  for (const unsigned char ch : state_dir) {
    hash ^= ch;
    hash *= 1099511628211ull;
  }
  std::wostringstream out;
  out << L"Local\\EXV-UiShell-" << std::hex << hash;
  return out.str();
}

class Win32UiShellSingleInstance final : public UiShellSingleInstance {
public:
  explicit Win32UiShellSingleInstance(const std::string &state_dir) {
    const std::wstring suffix = single_instance_name(state_dir);
    mutex_ = CreateMutexW(nullptr, TRUE, (suffix + L"-Mutex").c_str());
    primary_ = mutex_ != nullptr && GetLastError() != ERROR_ALREADY_EXISTS;
    wake_event_ = CreateEventW(nullptr, FALSE, FALSE,
                               (suffix + L"-Wake").c_str());
    if (!primary_ && wake_event_ != nullptr) {
      SetEvent(wake_event_);
    }
  }

  ~Win32UiShellSingleInstance() override {
    if (primary_ && mutex_ != nullptr) {
      ReleaseMutex(mutex_);
    }
    if (wake_event_ != nullptr) {
      CloseHandle(wake_event_);
    }
    if (mutex_ != nullptr) {
      CloseHandle(mutex_);
    }
  }

  bool is_primary() const noexcept override { return primary_; }

  void poll_wake_requests(const std::function<void()> &on_wake) override {
    if (!primary_ || wake_event_ == nullptr) {
      return;
    }
    if (WaitForSingleObject(wake_event_, 0) == WAIT_OBJECT_0 && on_wake) {
      on_wake();
    }
  }

private:
  HANDLE mutex_ = nullptr;
  HANDLE wake_event_ = nullptr;
  bool primary_ = true;
};

} // namespace

std::unique_ptr<UiShellSingleInstance>
acquire_ui_shell_single_instance(const std::string &state_dir) {
  return std::make_unique<Win32UiShellSingleInstance>(state_dir);
}

} // namespace exv::ui_shell
