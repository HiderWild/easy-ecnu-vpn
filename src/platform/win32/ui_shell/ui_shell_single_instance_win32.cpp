#include "app/ui_shell/ui_shell_single_instance.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <memory>
#include <string>

namespace exv::ui_shell {
namespace {

std::wstring single_instance_name(const std::string &suffix) {
  std::wstring out = L"Local\\ECNU-VPN-UiShell-";
  for (const unsigned char ch : suffix) {
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
        (ch >= '0' && ch <= '9')) {
      out.push_back(static_cast<wchar_t>(ch));
    } else {
      out.push_back(L'_');
    }
  }
  return out;
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
