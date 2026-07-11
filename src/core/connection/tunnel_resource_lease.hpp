#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace exv::connection::tunnel_resource_lease {

inline constexpr const char *kTunnelResourceActiveCode =
    "tunnel_resource_active";
inline constexpr const char *kTunnelResourceLockFailedCode =
    "tunnel_resource_lock_failed";

struct LeaseRecord {
  std::string lease_id;
  int owner_pid = -1;
  std::string owner;
  std::string profile_id;
  std::int64_t created_at_unix_ms = 0;
};

struct AcquireOptions {
  std::string config_dir;
  int owner_pid = -1;
  std::string owner;
  std::string profile_id;
  std::function<bool(int)> is_process_alive;
};

struct AcquireResult {
  bool acquired = false;
  bool stale_replaced = false;
  LeaseRecord record;
  std::string code;
  std::string message;
};

LeaseRecord read_record(const std::string &config_dir);
AcquireResult try_acquire(const AcquireOptions &options);
bool release_if_owner(const std::string &config_dir,
                      const std::string &lease_id);
void write_record_for_testing(const std::string &config_dir,
                              const LeaseRecord &record);

} // namespace exv::connection::tunnel_resource_lease
