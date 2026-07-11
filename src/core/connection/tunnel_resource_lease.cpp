#include "core/connection/tunnel_resource_lease.hpp"

#include "core/connection/connection_attempt.hpp"
#include "platform/common/process_control.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace exv::connection::tunnel_resource_lease {
namespace {

namespace fs = std::filesystem;

constexpr const char *kLeaseDirectoryName = "active-tunnel.lock";
constexpr const char *kLeaseOwnerFileName = "owner.json";
constexpr const char *kLeaseMutexFileName = "active-tunnel.mutex";

std::atomic<unsigned long long> lease_counter{0};

std::int64_t unix_ms_now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

fs::path config_path(const std::string &config_dir) {
  return fs::u8path(config_dir);
}

fs::path lease_path(const std::string &config_dir) {
  return config_path(config_dir) / kLeaseDirectoryName;
}

fs::path lease_owner_path(const std::string &config_dir) {
  return lease_path(config_dir) / kLeaseOwnerFileName;
}

fs::path mutex_path(const std::string &config_dir) {
  return config_path(config_dir) / kLeaseMutexFileName;
}

class LeaseMutex {
public:
  LeaseMutex() = default;
  ~LeaseMutex() { release(); }

  LeaseMutex(const LeaseMutex &) = delete;
  LeaseMutex &operator=(const LeaseMutex &) = delete;

  LeaseMutex(LeaseMutex &&other) noexcept { move_from(other); }
  LeaseMutex &operator=(LeaseMutex &&other) noexcept {
    if (this != &other) {
      release();
      move_from(other);
    }
    return *this;
  }

  static LeaseMutex acquire(const std::string &config_dir) {
    LeaseMutex mutex;
    std::error_code ec;
    fs::create_directories(config_path(config_dir), ec);
    if (ec) {
      return mutex;
    }

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

  void move_from(LeaseMutex &other) noexcept {
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

std::string make_lease_id(int owner_pid) {
  std::ostringstream out;
  out << "tunnel-lease-" << unix_ms_now() << "-" << owner_pid << "-"
      << ++lease_counter;
  return out.str();
}

nlohmann::json to_json_record(const LeaseRecord &record) {
  return nlohmann::json{{"lease_id", record.lease_id},
                        {"owner_pid", record.owner_pid},
                        {"owner", record.owner},
                        {"profile_id", record.profile_id},
                        {"created_at_unix_ms", record.created_at_unix_ms}};
}

LeaseRecord record_from_json(const nlohmann::json &json) {
  LeaseRecord record;
  if (!json.is_object()) {
    return record;
  }
  record.lease_id = json.value("lease_id", std::string());
  record.owner_pid = json.value("owner_pid", -1);
  record.owner = json.value("owner", std::string());
  record.profile_id = json.value("profile_id", std::string());
  record.created_at_unix_ms =
      json.value("created_at_unix_ms", static_cast<std::int64_t>(0));
  return record;
}

bool write_json_atomic(const fs::path &final_path, const nlohmann::json &json) {
  std::error_code ec;
  fs::create_directories(final_path.parent_path(), ec);
  if (ec) {
    return false;
  }

  const fs::path tmp_path =
      final_path.string() + ".tmp." +
      std::to_string(exv::connection_attempt::current_process_id());
  {
    std::ofstream out(tmp_path, std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
      return false;
    }
    out << json.dump(2);
    if (!out.good()) {
      return false;
    }
  }

  fs::remove(final_path, ec);
  ec.clear();
  fs::rename(tmp_path, final_path, ec);
  if (!ec) {
    return true;
  }

  std::error_code copy_ec;
  fs::copy_file(tmp_path, final_path, fs::copy_options::overwrite_existing,
                copy_ec);
  fs::remove(tmp_path, ec);
  return !copy_ec;
}

bool write_record(const std::string &config_dir, const LeaseRecord &record) {
  return write_json_atomic(lease_owner_path(config_dir), to_json_record(record));
}

bool read_json_record_path(const fs::path &path, LeaseRecord *out) {
  if (!out) {
    return false;
  }
  std::ifstream in(path);
  if (!in.is_open()) {
    return false;
  }
  try {
    const auto json = nlohmann::json::parse(in);
    *out = record_from_json(json);
    return true;
  } catch (...) {
    return false;
  }
}

bool owner_alive(const LeaseRecord &record, const AcquireOptions &options) {
  if (record.owner_pid <= 0) {
    return false;
  }
  if (options.is_process_alive) {
    return options.is_process_alive(record.owner_pid);
  }
  return exv::platform::is_process_alive(record.owner_pid);
}

AcquireResult active_result(const LeaseRecord &record) {
  AcquireResult result;
  result.acquired = false;
  result.record = record;
  result.code = kTunnelResourceActiveCode;
  result.message = "Another EXV tunnel is already active.";
  return result;
}

AcquireResult lock_failed_result(const std::string &message) {
  AcquireResult result;
  result.acquired = false;
  result.code = kTunnelResourceLockFailedCode;
  result.message = message;
  return result;
}

LeaseRecord acquired_record(const AcquireOptions &options) {
  LeaseRecord record;
  record.owner_pid =
      options.owner_pid > 0 ? options.owner_pid
                            : exv::connection_attempt::current_process_id();
  record.owner = options.owner.empty() ? "unknown" : options.owner;
  record.profile_id = options.profile_id;
  record.created_at_unix_ms = unix_ms_now();
  record.lease_id = make_lease_id(record.owner_pid);
  return record;
}

} // namespace

LeaseRecord read_record(const std::string &config_dir) {
  LeaseRecord record;
  if (config_dir.empty()) {
    return record;
  }

  const auto path = lease_path(config_dir);
  std::error_code ec;
  if (fs::is_directory(path, ec)) {
    read_json_record_path(lease_owner_path(config_dir), &record);
    return record;
  }
  read_json_record_path(path, &record);
  return record;
}

AcquireResult try_acquire(const AcquireOptions &options) {
  if (options.config_dir.empty()) {
    return lock_failed_result("Tunnel resource lease requires a config directory.");
  }

  std::error_code ec;
  fs::create_directories(config_path(options.config_dir), ec);
  if (ec) {
    return lock_failed_result("Failed to create tunnel resource lease directory.");
  }

  LeaseMutex mutex = LeaseMutex::acquire(options.config_dir);
  if (!mutex.acquired()) {
    return active_result(read_record(options.config_dir));
  }

  const auto existing = read_record(options.config_dir);
  AcquireResult result;
  if (!existing.lease_id.empty()) {
    if (owner_alive(existing, options)) {
      return active_result(existing);
    }
    result.stale_replaced = true;
    fs::remove_all(lease_path(options.config_dir), ec);
  }

  const auto record = acquired_record(options);
  if (!write_record(options.config_dir, record)) {
    return lock_failed_result("Failed to persist tunnel resource lease.");
  }

  result.acquired = true;
  result.record = record;
  return result;
}

bool release_if_owner(const std::string &config_dir,
                      const std::string &lease_id) {
  if (config_dir.empty() || lease_id.empty()) {
    return false;
  }

  LeaseMutex mutex = LeaseMutex::acquire(config_dir);
  if (!mutex.acquired()) {
    return false;
  }

  const auto current = read_record(config_dir);
  if (current.lease_id != lease_id) {
    return false;
  }

  std::error_code ec;
  fs::remove_all(lease_path(config_dir), ec);
  return !ec;
}

void write_record_for_testing(const std::string &config_dir,
                              const LeaseRecord &record) {
  (void)write_record(config_dir, record);
}

} // namespace exv::connection::tunnel_resource_lease
