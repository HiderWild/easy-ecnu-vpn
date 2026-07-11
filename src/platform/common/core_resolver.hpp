#pragma once

#include "platform/common/core_lifecycle_contract.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <functional>
#include <optional>
#include <string>

namespace exv::core::lifecycle {

enum class CoreResolveStatus {
  ReuseExisting,
  LaunchRequired,
  CoreCommBroken,
  CoreUnresponsive,
  CoreProtocolMismatch,
  CoreNotFound,
  CoreLaunchFailed,
  CoreVersionProbeFailed,
};

struct CoreResolveResult {
  CoreResolveStatus status = CoreResolveStatus::CoreNotFound;
  std::string ipc_path;
  std::string core_path;
  nlohmann::json hello;
  nlohmann::json registry_snapshot;
  std::string message;
};

struct CoreResolverDeps {
  std::function<bool(const std::string &ipc_path)> open_ipc_session;
  std::function<std::string(const std::string &request_line)>
      send_ipc_session_request;
  std::function<void()> close_ipc_session;
  std::function<bool(const std::string &ipc_path)> try_connect_ipc;
  std::function<std::string(const std::string &ipc_path,
                            const std::string &request_line)>
      send_ipc_request;
  std::function<void()> disconnect_ipc;
  std::function<bool(const std::string &core_path,
                     const std::string &state_dir,
                     const std::string &home_dir)> launch_core;
  std::function<std::string()> get_frontend_executable_path;
  std::function<std::string(const std::string &)> run_command_output;
  std::function<bool(int pid)> is_pid_alive;
  std::function<std::string()> get_state_dir;
  std::function<std::string()> get_home_dir;
  std::function<std::string(const std::string &)> get_env_var;
};

struct CoreResolveOptions {
  std::chrono::milliseconds hello_timeout{5000};
  int hello_retries = 1;
  std::string preferred_core_path;
};

CoreResolveResult resolve_core(const CoreResolveOptions &options = {},
                               const CoreResolverDeps &deps = {});

std::string core_resolve_status_code(CoreResolveStatus status);

std::string core_candidate_name();

std::optional<std::string> find_core_candidate(const std::string &frontend_path,
                                               const std::string &env_core_path,
                                               const std::string &path_var);

bool validate_core_version_output(const std::string &output);

bool is_self_reference(const std::string &candidate,
                       const std::string &frontend_path);

} // namespace exv::core::lifecycle
