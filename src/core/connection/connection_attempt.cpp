#include "core/connection/connection_attempt.hpp"

#include <atomic>
#include <chrono>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>
#include <thread>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace exv {
namespace connection_attempt {
// Begin inlined from core/connection/connection_attempt_internal include-unit
namespace {

namespace fs = std::filesystem;

constexpr const char *kRegistryFileName = "connect-attempt.json";
constexpr const char *kLockDirectoryName = "connect-attempt.lock";
constexpr const char *kLockOwnerFileName = "owner.json";
constexpr const char *kMutexFileName = "connect-attempt.mutex";

std::atomic<unsigned long long> attempt_counter{0};

std::int64_t unix_ms_now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string make_attempt_id(int owner_pid) {
  std::ostringstream out;
  out << "attempt-" << unix_ms_now() << "-" << owner_pid << "-"
      << ++attempt_counter;
  return out.str();
}

fs::path config_path(const std::string &config_dir) {
  return fs::u8path(config_dir);
}

fs::path lock_path(const std::string &config_dir) {
  return config_path(config_dir) / kLockDirectoryName;
}

fs::path lock_owner_path(const std::string &config_dir) {
  return lock_path(config_dir) / kLockOwnerFileName;
}

fs::path mutex_path(const std::string &config_dir) {
  return config_path(config_dir) / kMutexFileName;
}

class AttemptMutex {
public:
  AttemptMutex() = default;
  ~AttemptMutex() { release(); }

  AttemptMutex(const AttemptMutex &) = delete;
  AttemptMutex &operator=(const AttemptMutex &) = delete;

  AttemptMutex(AttemptMutex &&other) noexcept { move_from(other); }
  AttemptMutex &operator=(AttemptMutex &&other) noexcept {
    if (this != &other) {
      release();
      move_from(other);
    }
    return *this;
  }

  static AttemptMutex acquire(const std::string &config_dir) {
    AttemptMutex mutex;
    std::error_code ec;
    fs::create_directories(config_path(config_dir), ec);
    if (ec)
      return mutex;

#ifdef _WIN32
    mutex.handle_ =
        CreateFileA(mutex_path(config_dir).string().c_str(),
                    GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    mutex.acquired_ = mutex.handle_ != INVALID_HANDLE_VALUE;
#else
    mutex.fd_ = open(mutex_path(config_dir).string().c_str(),
                     O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (mutex.fd_ >= 0 && flock(mutex.fd_, LOCK_EX | LOCK_NB) == 0) {
      mutex.acquired_ = true;
    } else {
      mutex.release();
    }
#endif
    return mutex;
  }

  bool acquired() const { return acquired_; }

private:
  void release() noexcept {
#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
    }
#else
    if (fd_ >= 0) {
      flock(fd_, LOCK_UN);
      close(fd_);
      fd_ = -1;
    }
#endif
    acquired_ = false;
  }

  void move_from(AttemptMutex &other) noexcept {
    acquired_ = other.acquired_;
#ifdef _WIN32
    handle_ = other.handle_;
    other.handle_ = INVALID_HANDLE_VALUE;
#else
    fd_ = other.fd_;
    other.fd_ = -1;
#endif
    other.acquired_ = false;
  }

  bool acquired_ = false;
#ifdef _WIN32
  HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
  int fd_ = -1;
#endif
};

bool is_terminal_state(const std::string &state) {
  return state == "terminal" || state == "failed" || state == "stopped";
}

ProcessLiveness default_process_liveness(int pid) {
  if (pid <= 0)
    return ProcessLiveness::unknown;
#ifdef _WIN32
  // TODO: PID-only identity can be fooled by PID reuse. Persist process
  // creation time with owner_pid when the platform seam is widened.
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                               static_cast<DWORD>(pid));
  if (!process) {
    const DWORD error = GetLastError();
    // ERROR_INVALID_PARAMETER is Windows' "no such process" signal here.
    // ACCESS_DENIED means a protected process may exist, so keep the guard.
    if (error == ERROR_INVALID_PARAMETER)
      return ProcessLiveness::dead;
    if (error == ERROR_ACCESS_DENIED)
      return ProcessLiveness::alive;
    return ProcessLiveness::unknown;
  }

  DWORD exit_code = 0;
  const BOOL ok = GetExitCodeProcess(process, &exit_code);
  CloseHandle(process);
  if (!ok)
    return ProcessLiveness::unknown;
  return exit_code == STILL_ACTIVE ? ProcessLiveness::alive
                                   : ProcessLiveness::dead;
#else
  if (kill(static_cast<pid_t>(pid), 0) == 0)
    return ProcessLiveness::alive;
  if (errno == ESRCH)
    return ProcessLiveness::dead;
  if (errno == EPERM)
    return ProcessLiveness::alive;
  return ProcessLiveness::unknown;
#endif
}

ProcessLiveness process_liveness(int pid, const AcquireOptions &options) {
  if (pid <= 0)
    return ProcessLiveness::unknown;
  if (options.probe_process_liveness)
    return options.probe_process_liveness(pid);
  if (options.is_process_alive) {
    return options.is_process_alive(pid) ? ProcessLiveness::alive
                                         : ProcessLiveness::dead;
  }
  return default_process_liveness(pid);
}

bool all_owner_candidates_dead(const AttemptRecord &record,
                               const AcquireOptions &options) {
  bool saw_candidate = false;
  const int candidates[] = {record.owner_pid, record.helper_pid};
  for (const int pid : candidates) {
    if (pid <= 0)
      continue;
    saw_candidate = true;
    if (process_liveness(pid, options) != ProcessLiveness::dead)
      return false;
  }
  return saw_candidate;
}

AttemptRecord merge_attempt_metadata(const AttemptRecord &primary,
                                     const AttemptRecord &fallback) {
  AttemptRecord merged = primary;
  if (merged.attempt_id.empty())
    merged.attempt_id = fallback.attempt_id;
  if (merged.owner_pid <= 0)
    merged.owner_pid = fallback.owner_pid;
  if (merged.helper_pid <= 0)
    merged.helper_pid = fallback.helper_pid;
  if (merged.mode.empty())
    merged.mode = fallback.mode;
  if (merged.created_at_unix_ms == 0)
    merged.created_at_unix_ms = fallback.created_at_unix_ms;
  if (merged.state.empty())
    merged.state = fallback.state;
  if (merged.terminal_reason.empty())
    merged.terminal_reason = fallback.terminal_reason;
  return merged;
}

AttemptRecord record_from_json(const nlohmann::json &json) {
  AttemptRecord record;
  if (!json.is_object())
    return record;

  record.attempt_id = json.value("attempt_id", std::string());
  record.owner_pid = json.value("owner_pid", -1);
  record.helper_pid = json.value("helper_pid", -1);
  record.mode = json.value("mode", std::string());
  record.created_at_unix_ms =
      json.value("created_at_unix_ms", static_cast<std::int64_t>(0));
  record.state = json.value("state", std::string());
  record.terminal_reason = json.value("terminal_reason", std::string());
  return record;
}

bool write_json_atomic(const fs::path &final_path, const nlohmann::json &json) {
  std::error_code ec;
  fs::create_directories(final_path.parent_path(), ec);
  if (ec)
    return false;

  const fs::path tmp_path =
      final_path.string() + ".tmp." + std::to_string(current_process_id());

  {
    std::ofstream out(tmp_path, std::ios::out | std::ios::trunc);
    if (!out.is_open())
      return false;
    out << json.dump(2);
    if (!out.good())
      return false;
  }

  fs::remove(final_path, ec);
  ec.clear();
  fs::rename(tmp_path, final_path, ec);
  if (!ec)
    return true;

  std::error_code copy_ec;
  fs::copy_file(tmp_path, final_path, fs::copy_options::overwrite_existing,
                copy_ec);
  fs::remove(tmp_path, ec);
  return !copy_ec;
}

bool write_record(const std::string &config_dir, const AttemptRecord &record) {
  return write_json_atomic(fs::u8path(registry_path(config_dir)),
                           to_json(record));
}

bool write_lock_owner(const fs::path &dir, const AttemptRecord &record) {
  return write_json_atomic(dir / kLockOwnerFileName, to_json(record));
}

AcquireResult active_result(const AttemptRecord &record) {
  AcquireResult result;
  result.acquired = false;
  result.record = record;
  result.code = kConnectionAttemptActiveCode;
  result.message = "A native VPN connection attempt is already active.";
  return result;
}

AcquireResult lock_failed_result(const std::string &message) {
  AcquireResult result;
  result.acquired = false;
  result.code = kConnectionAttemptLockFailedCode;
  result.message = message;
  return result;
}

bool read_json_record_path(const fs::path &path, AttemptRecord *out) {
  if (!out)
    return false;

  std::ifstream in(path);
  if (!in.is_open())
    return false;

  try {
    nlohmann::json json = nlohmann::json::parse(in);
    *out = record_from_json(json);
    return true;
  } catch (...) {
    return false;
  }
}

bool read_lock_record(const std::string &config_dir, AttemptRecord *out) {
  return read_json_record_path(lock_owner_path(config_dir), out);
}

bool remove_owned_lock(const std::string &config_dir,
                       const std::string &attempt_id) {
  AttemptRecord lock_record;
  if (!attempt_id.empty() && read_lock_record(config_dir, &lock_record) &&
      lock_record.attempt_id != attempt_id) {
    return false;
  }
  if (!attempt_id.empty() && !read_lock_record(config_dir, &lock_record))
    return false;

  std::error_code ec;
  fs::remove_all(lock_path(config_dir), ec);
  return !ec;
}

bool remove_lock_for_recovery(const std::string &config_dir) {
  std::error_code ec;
  fs::remove_all(lock_path(config_dir), ec);
  return !ec;
}

bool install_owned_lock(const std::string &config_dir,
                        const AttemptRecord &record) {
  std::error_code ec;
  const fs::path tmp_dir =
      config_path(config_dir) /
      (std::string(kLockDirectoryName) + ".tmp." + record.attempt_id);
  fs::remove_all(tmp_dir, ec);
  ec.clear();
  fs::create_directories(tmp_dir, ec);
  if (ec)
    return false;
  if (!write_lock_owner(tmp_dir, record)) {
    fs::remove_all(tmp_dir, ec);
    return false;
  }

  ec.clear();
  fs::rename(tmp_dir, lock_path(config_dir), ec);
  if (!ec)
    return true;

  fs::remove_all(tmp_dir, ec);
  return false;
}

AcquireResult acquired_result(const std::string &config_dir,
                              const AcquireOptions &options) {
  AttemptRecord record;
  record.owner_pid =
      options.owner_pid > 0 ? options.owner_pid : current_process_id();
  record.mode = options.mode.empty() ? "native" : options.mode;
  record.attempt_id = make_attempt_id(record.owner_pid);
  record.created_at_unix_ms = unix_ms_now();
  record.state = "active";

  if (!install_owned_lock(config_dir, record))
    return lock_failed_result("Failed to acquire connection attempt lock.");

  if (!write_record(config_dir, record)) {
    remove_owned_lock(config_dir, record.attempt_id);
    return lock_failed_result("Failed to persist connection attempt state.");
  }

  AcquireResult result;
  result.acquired = true;
  result.record = record;
  return result;
}

AttemptRecord unknown_active_record() {
  AttemptRecord record;
  record.state = "active";
  return record;
}

} // namespace
// End inlined from core/connection/connection_attempt_internal include-unit
// Begin inlined from core/connection/connection_attempt_public include-unit
int current_process_id() {
#ifdef _WIN32
  return static_cast<int>(GetCurrentProcessId());
#else
  return static_cast<int>(getpid());
#endif
}

std::string registry_path(const std::string &config_dir) {
  return (config_path(config_dir) / kRegistryFileName).string();
}

nlohmann::json to_json(const AttemptRecord &record) {
  return nlohmann::json{{"attempt_id", record.attempt_id},
                        {"owner_pid", record.owner_pid},
                        {"helper_pid", record.helper_pid},
                        {"mode", record.mode},
                        {"created_at_unix_ms", record.created_at_unix_ms},
                        {"state", record.state},
                        {"terminal_reason", record.terminal_reason}};
}

TerminalAttemptScope::TerminalAttemptScope(std::string config_dir,
                                           std::string attempt_id,
                                           std::string reason)
    : config_dir_(std::move(config_dir)), attempt_id_(std::move(attempt_id)),
      reason_(std::move(reason)) {}

TerminalAttemptScope::~TerminalAttemptScope() {
  if (!dismissed_ && !config_dir_.empty() && !attempt_id_.empty()) {
    mark_terminal_if_current(config_dir_, attempt_id_,
                             reason_.empty() ? "scope_exit" : reason_);
  }
}

TerminalAttemptScope::TerminalAttemptScope(
    TerminalAttemptScope &&other) noexcept
    : config_dir_(std::move(other.config_dir_)),
      attempt_id_(std::move(other.attempt_id_)),
      reason_(std::move(other.reason_)), dismissed_(other.dismissed_) {
  other.dismissed_ = true;
}

TerminalAttemptScope &TerminalAttemptScope::operator=(
    TerminalAttemptScope &&other) noexcept {
  if (this != &other) {
    if (!dismissed_ && !config_dir_.empty() && !attempt_id_.empty()) {
      mark_terminal_if_current(config_dir_, attempt_id_,
                               reason_.empty() ? "scope_exit" : reason_);
    }
    config_dir_ = std::move(other.config_dir_);
    attempt_id_ = std::move(other.attempt_id_);
    reason_ = std::move(other.reason_);
    dismissed_ = other.dismissed_;
    other.dismissed_ = true;
  }
  return *this;
}

void TerminalAttemptScope::dismiss() noexcept { dismissed_ = true; }

bool read_record(const std::string &config_dir, AttemptRecord *out) {
  return read_json_record_path(fs::u8path(registry_path(config_dir)), out);
}

AcquireResult try_acquire(const AcquireOptions &options) {
  if (options.config_dir.empty()) {
    return lock_failed_result(
        "Connection attempt guard requires a config directory.");
  }

  std::error_code ec;
  fs::create_directories(config_path(options.config_dir), ec);
  if (ec)
    return lock_failed_result("Failed to create connection attempt directory.");

  AttemptMutex mutex = AttemptMutex::acquire(options.config_dir);
  if (!mutex.acquired())
    return active_result(unknown_active_record());

  const bool lock_exists = fs::exists(lock_path(options.config_dir), ec);
  if (lock_exists) {
    AttemptRecord lock_record;
    if (read_lock_record(options.config_dir, &lock_record)) {
      AttemptRecord effective_record = lock_record;
      AttemptRecord registry_record;
      if (read_record(options.config_dir, &registry_record) &&
          registry_record.attempt_id == lock_record.attempt_id) {
        effective_record = merge_attempt_metadata(registry_record, lock_record);
      }

      if (!is_terminal_state(effective_record.state) &&
          !all_owner_candidates_dead(effective_record, options))
        return active_result(effective_record);
      if (!remove_owned_lock(options.config_dir, lock_record.attempt_id))
        return active_result(effective_record);
    } else {
      AttemptRecord registry_record;
      if (read_record(options.config_dir, &registry_record) &&
          !is_terminal_state(registry_record.state)) {
        if (!all_owner_candidates_dead(registry_record, options))
          return active_result(registry_record);
      }
      remove_lock_for_recovery(options.config_dir);
    }
  }

  AttemptRecord current;
  if (read_record(options.config_dir, &current) &&
      !is_terminal_state(current.state)) {
    if (!all_owner_candidates_dead(current, options))
      return active_result(current);
  }

  return acquired_result(options.config_dir, options);
}

bool update_pids_if_current(const std::string &config_dir,
                            const std::string &attempt_id, int helper_pid) {
  AttemptMutex mutex = AttemptMutex::acquire(config_dir);
  if (!mutex.acquired())
    return false;

  AttemptRecord record;
  if (!read_record(config_dir, &record) || record.attempt_id != attempt_id)
    return false;

  if (helper_pid > 0)
    record.helper_pid = helper_pid;
  if (!write_record(config_dir, record))
    return false;

  AttemptRecord lock_record;
  if (read_lock_record(config_dir, &lock_record) &&
      lock_record.attempt_id == attempt_id) {
    write_lock_owner(lock_path(config_dir),
                     merge_attempt_metadata(record, lock_record));
  }
  return true;
}

namespace {

enum class TerminalMarkStatus { marked, not_current, retryable_failure };

TerminalMarkStatus mark_terminal_if_current_once(const std::string &config_dir,
                                                 const std::string &attempt_id,
                                                 const std::string &reason) {
  AttemptMutex mutex = AttemptMutex::acquire(config_dir);
  if (!mutex.acquired())
    return TerminalMarkStatus::retryable_failure;

  AttemptRecord record;
  if (!read_record(config_dir, &record))
    return TerminalMarkStatus::retryable_failure;
  if (record.attempt_id != attempt_id)
    return TerminalMarkStatus::not_current;

  record.state = "terminal";
  record.terminal_reason = reason;
  const bool wrote = write_record(config_dir, record);
  if (!wrote)
    return TerminalMarkStatus::retryable_failure;

  remove_owned_lock(config_dir, attempt_id);
  return TerminalMarkStatus::marked;
}

} // namespace

bool mark_terminal_if_current(const std::string &config_dir,
                              const std::string &attempt_id,
                              const std::string &reason) {
  constexpr int kMaxTerminalMarkAttempts = 24;
  constexpr auto kRetryDelay = std::chrono::milliseconds(25);

  for (int attempt = 0; attempt < kMaxTerminalMarkAttempts; ++attempt) {
    const TerminalMarkStatus status =
        mark_terminal_if_current_once(config_dir, attempt_id, reason);
    if (status == TerminalMarkStatus::marked)
      return true;
    if (status == TerminalMarkStatus::not_current)
      return false;
    if (attempt + 1 < kMaxTerminalMarkAttempts)
      std::this_thread::sleep_for(kRetryDelay);
  }
  return false;
}

bool mark_terminal(const std::string &config_dir, const std::string &reason) {
  AttemptMutex mutex = AttemptMutex::acquire(config_dir);
  if (!mutex.acquired())
    return false;

  AttemptRecord record;
  if (read_record(config_dir, &record)) {
    record.state = "terminal";
    record.terminal_reason = reason;
    write_record(config_dir, record);
  }

  if (!record.attempt_id.empty())
    return remove_owned_lock(config_dir, record.attempt_id);
  return remove_lock_for_recovery(config_dir);
}
// End inlined from core/connection/connection_attempt_public include-unit
} // namespace connection_attempt
} // namespace exv
