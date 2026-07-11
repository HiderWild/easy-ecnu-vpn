#pragma once

#include <cstdint>
#include <functional>
#include <nlohmann/json.hpp>
#include <string>

namespace exv {
namespace connection_attempt {

inline constexpr const char *kConnectionAttemptActiveCode =
    "connection_attempt_active";
inline constexpr const char *kConnectionAttemptLockFailedCode =
    "connection_attempt_lock_failed";

struct AttemptRecord {
  std::string attempt_id;
  int owner_pid = -1;
  int helper_pid = -1;
  std::string mode;
  std::int64_t created_at_unix_ms = 0;
  std::string state;
  std::string terminal_reason;
};

enum class ProcessLiveness { alive, dead, unknown };

struct AcquireOptions {
  std::string config_dir;
  std::string mode = "native";
  int owner_pid = -1;
  std::function<ProcessLiveness(int)> probe_process_liveness;
  std::function<bool(int)> is_process_alive;
};

struct AcquireResult {
  bool acquired = false;
  AttemptRecord record;
  std::string code;
  std::string message;
};

int current_process_id();
std::string registry_path(const std::string &config_dir);
nlohmann::json to_json(const AttemptRecord &record);

// RAII guard for a connection attempt. Acquired when a connect job starts;
// on destruction (job exit, including failure/exception) it marks the attempt
// terminal and releases the in-flight guard, so a subsequent connect/reconnect
// is never blocked by a dead prior attempt. Stale-owner recovery in
// try_acquire() provides a second safety net if the scope was bypassed.
class TerminalAttemptScope {
public:
  TerminalAttemptScope(std::string config_dir, std::string attempt_id,
                       std::string reason);
  ~TerminalAttemptScope();

  TerminalAttemptScope(const TerminalAttemptScope &) = delete;
  TerminalAttemptScope &operator=(const TerminalAttemptScope &) = delete;

  TerminalAttemptScope(TerminalAttemptScope &&other) noexcept;
  TerminalAttemptScope &operator=(TerminalAttemptScope &&other) noexcept;

  void dismiss() noexcept;

private:
  std::string config_dir_;
  std::string attempt_id_;
  std::string reason_;
  bool dismissed_ = false;
};

bool read_record(const std::string &config_dir, AttemptRecord *out);
AcquireResult try_acquire(const AcquireOptions &options);
bool update_pids_if_current(const std::string &config_dir,
                            const std::string &attempt_id, int helper_pid);
bool mark_terminal_if_current(const std::string &config_dir,
                              const std::string &attempt_id,
                              const std::string &reason);
bool mark_terminal(const std::string &config_dir, const std::string &reason);

} // namespace connection_attempt
} // namespace exv
