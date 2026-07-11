#include "app/ui_shell/core_process_manager.hpp"

#include "cli/pipe_client.hpp"
#include "core/lifecycle/core_paths.hpp"
#include "platform/common/core_resolver_platform_deps.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <deque>
#include <filesystem>
#include <memory>
#include <thread>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if !defined(_WIN32)
extern char **environ;
#endif

namespace exv::ui_shell {

namespace {

#if defined(_WIN32)

void close_handle(HANDLE &handle) {
  if (handle && handle != INVALID_HANDLE_VALUE) {
    CloseHandle(handle);
    handle = nullptr;
  }
}

std::wstring wide_from_utf8(const std::string &value) {
  if (value.empty()) {
    return {};
  }
  const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                       value.data(),
                                       static_cast<int>(value.size()), nullptr,
                                       0);
  if (size <= 0) {
    return {};
  }
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                      static_cast<int>(value.size()), out.data(), size);
  return out;
}

std::wstring quote_windows_argument(const std::string &value) {
  if (value.empty()) {
    return L"\"\"";
  }

  const bool needs_quotes =
      value.find_first_of(" \t\n\v\"") != std::string::npos;
  std::wstring wide = wide_from_utf8(value);
  if (!needs_quotes) {
    return wide;
  }

  std::wstring quoted;
  quoted.push_back(L'"');
  std::size_t backslashes = 0;
  for (wchar_t ch : wide) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    if (ch == L'"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(ch);
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, L'\\');
    backslashes = 0;
    quoted.push_back(ch);
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'"');
  return quoted;
}

std::wstring build_windows_command_line(const CoreProcessLaunch &launch) {
  std::wstring command = quote_windows_argument(launch.exv_path);
  for (const std::string &arg : build_core_process_arguments(launch)) {
    command.push_back(L' ');
    command.append(quote_windows_argument(arg));
  }
  return command;
}

class WindowsCoreProcessTransport final : public CoreRpcTransport {
public:
  explicit WindowsCoreProcessTransport(const CoreProcessLaunch &launch) {
    start(launch);
  }

  ~WindowsCoreProcessTransport() override {
    close();
    close_handle(stdout_read_);
    close_handle(process_);
  }

  void close() override {
    close_handle(stdin_write_);

    if (process_) {
      const DWORD wait_result = WaitForSingleObject(process_, 2000);
      if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(process_, 1);
        WaitForSingleObject(process_, 1000);
      }
    }
  }

  WindowsCoreProcessTransport(const WindowsCoreProcessTransport &) = delete;
  WindowsCoreProcessTransport &operator=(const WindowsCoreProcessTransport &) =
      delete;

  bool write_line(const std::string &line) override {
    if (!is_started()) {
      return false;
    }

    std::string payload = line;
    payload.push_back('\n');

    const char *cursor = payload.data();
    std::size_t remaining = payload.size();
    while (remaining > 0) {
      const DWORD chunk =
          static_cast<DWORD>(std::min<std::size_t>(remaining, 64 * 1024));
      DWORD written = 0;
      if (!WriteFile(stdin_write_, cursor, chunk, &written, nullptr) ||
          written == 0) {
        return false;
      }
      cursor += written;
      remaining -= written;
    }
    return true;
  }

  bool read_line(std::string &line) override {
    if (!is_started()) {
      return false;
    }
    if (pop_buffered_line(line)) {
      return true;
    }

    while (read_stdout_chunk(0)) {
      if (pop_buffered_line(line)) {
        return true;
      }
    }
    return false;
  }

  bool read_available_line(std::string &line) override {
    if (!is_started()) {
      return false;
    }
    if (pop_buffered_line(line)) {
      return true;
    }

    DWORD available = 0;
    if (!PeekNamedPipe(stdout_read_, nullptr, 0, nullptr, &available, nullptr) ||
        available == 0) {
      return false;
    }

    while (available > 0) {
      if (!read_stdout_chunk(available)) {
        return false;
      }
      if (pop_buffered_line(line)) {
        return true;
      }
      available = 0;
      if (!PeekNamedPipe(stdout_read_, nullptr, 0, nullptr, &available,
                         nullptr)) {
        return false;
      }
    }
    return false;
  }

private:
  void start(const CoreProcessLaunch &launch) {
    if (launch.exv_path.empty() || !launch.use_stdin) {
      return;
    }

    SECURITY_ATTRIBUTES security_attributes{};
    security_attributes.nLength = sizeof(security_attributes);
    security_attributes.bInheritHandle = TRUE;

    HANDLE stdin_read = nullptr;
    HANDLE stdout_write = nullptr;
    if (!CreatePipe(&stdin_read, &stdin_write_, &security_attributes, 0)) {
      return;
    }
    if (!SetHandleInformation(stdin_write_, HANDLE_FLAG_INHERIT, 0)) {
      close_handle(stdin_read);
      close_handle(stdin_write_);
      return;
    }

    if (!CreatePipe(&stdout_read_, &stdout_write, &security_attributes, 0)) {
      close_handle(stdin_read);
      close_handle(stdin_write_);
      return;
    }
    if (!SetHandleInformation(stdout_read_, HANDLE_FLAG_INHERIT, 0)) {
      close_handle(stdin_read);
      close_handle(stdin_write_);
      close_handle(stdout_read_);
      close_handle(stdout_write);
      return;
    }

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
    startup_info.hStdInput = stdin_read;
    startup_info.hStdOutput = stdout_write;
    startup_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION process_info{};
    std::wstring app_path = wide_from_utf8(launch.exv_path);
    std::wstring command_line = build_windows_command_line(launch);
    std::wstring current_dir;
    const std::filesystem::path parent =
        std::filesystem::path(launch.exv_path).parent_path();
    if (!parent.empty()) {
      current_dir = parent.wstring();
    }

    const BOOL created = CreateProcessW(
        app_path.empty() ? nullptr : app_path.c_str(), command_line.data(),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
        current_dir.empty() ? nullptr : current_dir.c_str(), &startup_info,
        &process_info);

    close_handle(stdin_read);
    close_handle(stdout_write);

    if (!created) {
      close_handle(stdin_write_);
      close_handle(stdout_read_);
      return;
    }

    process_ = process_info.hProcess;
    CloseHandle(process_info.hThread);
  }

  bool is_started() const {
    return process_ && stdin_write_ && stdout_read_;
  }

  bool read_stdout_chunk(DWORD available_bytes) {
    char buffer[4096];
    const DWORD bytes_to_read =
        available_bytes == 0
            ? static_cast<DWORD>(sizeof(buffer))
            : std::min<DWORD>(available_bytes, static_cast<DWORD>(sizeof(buffer)));
    DWORD bytes_read = 0;
    if (!ReadFile(stdout_read_, buffer, bytes_to_read, &bytes_read, nullptr) ||
        bytes_read == 0) {
      return false;
    }
    read_buffer_.append(buffer, buffer + bytes_read);
    return true;
  }

  bool pop_buffered_line(std::string &line) {
    const std::string::size_type newline = read_buffer_.find('\n');
    if (newline == std::string::npos) {
      return false;
    }
    line = read_buffer_.substr(0, newline);
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    read_buffer_.erase(0, newline + 1);
    return true;
  }

  HANDLE process_ = nullptr;
  HANDLE stdin_write_ = nullptr;
  HANDLE stdout_read_ = nullptr;
  std::string read_buffer_;
};

#endif

#if !defined(_WIN32)

constexpr std::chrono::milliseconds kCoreProcessReadTimeout{300000};
constexpr std::chrono::milliseconds kCoreProcessWriteTimeout{30000};

void close_fd(int &fd) {
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
}

bool move_fd_above_stdio(int &fd) {
  if (fd < 0 || fd > STDERR_FILENO) {
    return fd >= 0;
  }

  const int moved = fcntl(fd, F_DUPFD, STDERR_FILENO + 1);
  if (moved < 0) {
    return false;
  }
  close_fd(fd);
  fd = moved;
  return true;
}

bool wait_for_fd(int fd, short events, std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return false;
    }

    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
    pollfd descriptor{};
    descriptor.fd = fd;
    descriptor.events = events;
    const int ready =
        poll(&descriptor, 1, static_cast<int>(remaining.count()));
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (ready == 0) {
      return false;
    }
    if ((descriptor.revents & events) != 0) {
      return true;
    }
    if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      return false;
    }
  }
}

class PosixCoreProcessTransport final : public CoreRpcTransport {
public:
  explicit PosixCoreProcessTransport(const CoreProcessLaunch &launch) {
    start(launch);
  }

  ~PosixCoreProcessTransport() override {
    close();
    close_fd(stdout_read_);
  }

  void close() override {
    close_fd(stdin_write_);

    if (pid_ > 0) {
      wait_for_exit(std::chrono::milliseconds(2000));
      if (pid_ > 0) {
        kill(pid_, SIGTERM);
        wait_for_exit(std::chrono::milliseconds(1000));
      }
      if (pid_ > 0) {
        kill(pid_, SIGKILL);
        while (waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {
        }
        pid_ = -1;
      }
    }
  }

  PosixCoreProcessTransport(const PosixCoreProcessTransport &) = delete;
  PosixCoreProcessTransport &operator=(const PosixCoreProcessTransport &) =
      delete;

  bool write_line(const std::string &line) override {
    if (!is_started()) {
      return false;
    }

    std::string payload = line;
    payload.push_back('\n');

    const char *cursor = payload.data();
    std::size_t remaining = payload.size();
    while (remaining > 0) {
      if (!wait_for_fd(stdin_write_, POLLOUT, kCoreProcessWriteTimeout)) {
        return false;
      }
      const std::size_t chunk =
          std::min<std::size_t>(remaining, 64 * 1024);
      const ssize_t written = write(stdin_write_, cursor, chunk);
      if (written < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (written == 0) {
        return false;
      }
      cursor += written;
      remaining -= static_cast<std::size_t>(written);
    }
    return true;
  }

  bool read_line(std::string &line) override {
    if (!is_started()) {
      return false;
    }
    if (pop_buffered_line(line)) {
      return true;
    }

    while (read_stdout_chunk()) {
      if (pop_buffered_line(line)) {
        return true;
      }
    }
    return false;
  }

  bool read_available_line(std::string &line) override {
    if (!is_started()) {
      return false;
    }
    if (pop_buffered_line(line)) {
      return true;
    }

    pollfd descriptor{};
    descriptor.fd = stdout_read_;
    descriptor.events = POLLIN;
    for (;;) {
      const int ready = poll(&descriptor, 1, 0);
      if (ready < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (ready == 0 || (descriptor.revents & POLLIN) == 0) {
        return false;
      }
      if (!read_stdout_chunk()) {
        return false;
      }
      if (pop_buffered_line(line)) {
        return true;
      }
    }
  }

private:
  void start(const CoreProcessLaunch &launch) {
    if (launch.exv_path.empty() || !launch.use_stdin) {
      return;
    }

    std::vector<std::string> arguments;
    arguments.emplace_back(launch.exv_path);
    for (const std::string &arg : build_core_process_arguments(launch)) {
      arguments.emplace_back(arg);
    }
    std::vector<char *> argv;
    argv.reserve(arguments.size() + 1);
    for (std::string &arg : arguments) {
      argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    int stdin_pipe[2]{-1, -1};
    int stdout_pipe[2]{-1, -1};
    if (pipe(stdin_pipe) != 0) {
      return;
    }
    if (pipe(stdout_pipe) != 0) {
      close_fd(stdin_pipe[0]);
      close_fd(stdin_pipe[1]);
      return;
    }

    if (!move_fd_above_stdio(stdin_pipe[0]) ||
        !move_fd_above_stdio(stdin_pipe[1]) ||
        !move_fd_above_stdio(stdout_pipe[0]) ||
        !move_fd_above_stdio(stdout_pipe[1])) {
      close_fd(stdin_pipe[0]);
      close_fd(stdin_pipe[1]);
      close_fd(stdout_pipe[0]);
      close_fd(stdout_pipe[1]);
      return;
    }

    posix_spawn_file_actions_t file_actions{};
    if (posix_spawn_file_actions_init(&file_actions) != 0) {
      close_fd(stdin_pipe[0]);
      close_fd(stdin_pipe[1]);
      close_fd(stdout_pipe[0]);
      close_fd(stdout_pipe[1]);
      return;
    }

    bool actions_ok = true;
    actions_ok = actions_ok &&
                 posix_spawn_file_actions_adddup2(
                     &file_actions, stdin_pipe[0], STDIN_FILENO) == 0;
    actions_ok = actions_ok &&
                 posix_spawn_file_actions_adddup2(
                     &file_actions, stdout_pipe[1], STDOUT_FILENO) == 0;
    actions_ok = actions_ok &&
                 posix_spawn_file_actions_addclose(&file_actions,
                                                   stdin_pipe[0]) == 0;
    actions_ok = actions_ok &&
                 posix_spawn_file_actions_addclose(&file_actions,
                                                   stdin_pipe[1]) == 0;
    actions_ok = actions_ok &&
                 posix_spawn_file_actions_addclose(&file_actions,
                                                   stdout_pipe[0]) == 0;
    actions_ok = actions_ok &&
                 posix_spawn_file_actions_addclose(&file_actions,
                                                   stdout_pipe[1]) == 0;
    if (!actions_ok) {
      posix_spawn_file_actions_destroy(&file_actions);
      close_fd(stdin_pipe[0]);
      close_fd(stdin_pipe[1]);
      close_fd(stdout_pipe[0]);
      close_fd(stdout_pipe[1]);
      return;
    }

    pid_t child = -1;
    const int spawn_result =
        posix_spawn(&child, launch.exv_path.c_str(), &file_actions, nullptr,
                    argv.data(), environ);
    posix_spawn_file_actions_destroy(&file_actions);
    if (spawn_result != 0) {
      close_fd(stdin_pipe[0]);
      close_fd(stdin_pipe[1]);
      close_fd(stdout_pipe[0]);
      close_fd(stdout_pipe[1]);
      return;
    }

    pid_ = child;
    stdin_write_ = stdin_pipe[1];
    stdout_read_ = stdout_pipe[0];
    close_fd(stdin_pipe[0]);
    close_fd(stdout_pipe[1]);
  }

  bool is_started() const {
    return pid_ > 0 && stdin_write_ >= 0 && stdout_read_ >= 0;
  }

  bool read_stdout_chunk() {
    if (!wait_for_fd(stdout_read_, POLLIN, kCoreProcessReadTimeout)) {
      return false;
    }

    char buffer[4096];
    for (;;) {
      const ssize_t bytes_read = read(stdout_read_, buffer, sizeof(buffer));
      if (bytes_read < 0) {
        if (errno == EINTR) {
          continue;
        }
        return false;
      }
      if (bytes_read == 0) {
        return false;
      }
      read_buffer_.append(buffer, buffer + bytes_read);
      return true;
    }
  }

  bool pop_buffered_line(std::string &line) {
    const std::string::size_type newline = read_buffer_.find('\n');
    if (newline == std::string::npos) {
      return false;
    }
    line = read_buffer_.substr(0, newline);
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    read_buffer_.erase(0, newline + 1);
    return true;
  }

  void wait_for_exit(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (pid_ > 0 && std::chrono::steady_clock::now() < deadline) {
      const pid_t result = waitpid(pid_, nullptr, WNOHANG);
      if (result == pid_) {
        pid_ = -1;
        return;
      }
      if (result < 0 && errno != EINTR) {
        pid_ = -1;
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
  }

  pid_t pid_ = -1;
  int stdin_write_ = -1;
  int stdout_read_ = -1;
  std::string read_buffer_;
};

#endif

class ClosedCoreProcessTransport final : public CoreRpcTransport {
public:
  bool write_line(const std::string &) override {
    return false;
  }

  bool read_line(std::string &) override {
    return false;
  }
};

class PipeCoreRpcTransport final : public CoreRpcTransport {
public:
  explicit PipeCoreRpcTransport(std::string ipc_path)
      : ipc_path_(std::move(ipc_path)) {}

  void close() override {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      closed_ = true;
      pending_.clear();
    }
    std::lock_guard<std::mutex> client_lock(client_mutex_);
    client_.disconnect();
    cv_.notify_all();
  }

  bool write_line(const std::string &line) override {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (closed_ || ipc_path_.empty()) {
        return false;
      }
      pending_.push_back(line);
    }
    cv_.notify_one();
    return true;
  }

  bool read_line(std::string &line) override {
    std::string request;
    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait(lock, [this] { return closed_ || !pending_.empty(); });
      if (closed_ || pending_.empty()) {
        return false;
      }
      request = std::move(pending_.front());
      pending_.pop_front();
    }

    {
      std::lock_guard<std::mutex> client_lock(client_mutex_);
      if (!client_.is_connected() && !client_.connect(ipc_path_)) {
        return false;
      }
      line = client_.send_request(request);
      if (!line.empty()) {
        return true;
      }

      client_.disconnect();
      if (!client_.connect(ipc_path_)) {
        return false;
      }
      line = client_.send_request(request);
      if (line.empty()) {
        client_.disconnect();
        return false;
      }
    }
    return true;
  }

  bool read_available_line(std::string &) override { return false; }

private:
  std::string ipc_path_;
  std::mutex mutex_;
  std::mutex client_mutex_;
  std::condition_variable cv_;
  std::deque<std::string> pending_;
  exv::cli::PipeClient client_;
  bool closed_ = false;
};

} // namespace

std::vector<std::string> build_core_process_arguments(
    const CoreProcessLaunch &launch) {
  std::vector<std::string> args{"--mode=core"};
  if (!launch.state_dir.empty()) {
    args.emplace_back("--config-dir");
    args.emplace_back(launch.state_dir);
  }
  if (!launch.runtime_dir.empty()) {
    args.emplace_back("--home");
    args.emplace_back(launch.runtime_dir);
  }
  if (!launch.use_stdin) {
    args.emplace_back("--daemon");
  }
  return args;
}

void configure_core_process_transport_signal_policy() {
#if !defined(_WIN32)
  struct sigaction action {};
  action.sa_handler = SIG_IGN;
  sigemptyset(&action.sa_mask);
  ::sigaction(SIGPIPE, &action, nullptr);
#endif
}

std::unique_ptr<CoreRpcTransport> create_core_process_transport(
    const CoreProcessLaunch &launch) {
  if (!launch.use_stdin) {
    return std::make_unique<PipeCoreRpcTransport>(
        exv::core::lifecycle::core_ipc_path(launch.state_dir));
  }
#if defined(_WIN32)
  return std::make_unique<WindowsCoreProcessTransport>(launch);
#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
  return std::make_unique<PosixCoreProcessTransport>(launch);
#else
  (void)launch;
  return std::make_unique<ClosedCoreProcessTransport>();
#endif
}

exv::core::lifecycle::CoreResolveResult classify_core_state(
    const exv::core::lifecycle::CoreResolveOptions &options,
    const exv::core::lifecycle::CoreResolverDeps &deps) {
  auto effective_deps = (deps.open_ipc_session || deps.try_connect_ipc)
                            ? deps
                            : exv::core::lifecycle::make_platform_core_resolver_deps();
  return exv::core::lifecycle::resolve_core(options, effective_deps);
}

} // namespace exv::ui_shell
