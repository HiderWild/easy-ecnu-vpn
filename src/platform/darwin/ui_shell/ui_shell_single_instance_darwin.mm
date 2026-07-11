#include "app/ui_shell/ui_shell_single_instance.hpp"

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace exv::ui_shell {
namespace {

class FileLockUiShellSingleInstance final : public UiShellSingleInstance {
public:
  explicit FileLockUiShellSingleInstance(const std::string &state_dir) {
    root_ = std::filesystem::path(state_dir.empty() ? "." : state_dir);
    std::filesystem::create_directories(root_);
    lock_path_ = root_ / "ui-shell.lock";
    wake_path_ = root_ / "ui-shell.wake";
    fd_ = open(lock_path_.string().c_str(), O_CREAT | O_RDWR, 0600);
    primary_ = fd_ >= 0 && flock(fd_, LOCK_EX | LOCK_NB) == 0;
    if (!primary_) {
      std::ofstream(wake_path_).close();
    }
  }

  ~FileLockUiShellSingleInstance() override {
    if (fd_ >= 0) {
      if (primary_) {
        flock(fd_, LOCK_UN);
      }
      close(fd_);
    }
  }

  bool is_primary() const noexcept override { return primary_; }

  void poll_wake_requests(const std::function<void()> &on_wake) override {
    if (!primary_ || !std::filesystem::exists(wake_path_)) {
      return;
    }
    std::filesystem::remove(wake_path_);
    if (on_wake) {
      on_wake();
    }
  }

private:
  std::filesystem::path root_;
  std::filesystem::path lock_path_;
  std::filesystem::path wake_path_;
  int fd_ = -1;
  bool primary_ = true;
};

} // namespace

std::unique_ptr<UiShellSingleInstance>
acquire_ui_shell_single_instance(const std::string &state_dir) {
  return std::make_unique<FileLockUiShellSingleInstance>(state_dir);
}

} // namespace exv::ui_shell
