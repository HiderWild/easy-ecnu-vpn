#include "platform/common/core_resolver.hpp"

#include "contracts/generated/system_contract.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/core_lifecycle_contract.hpp"
#include "platform/common/process_utils.hpp"
#include "runtime/runtime_context.hpp"

#include <cstdlib>
#include <filesystem>
#include <regex>
#include <sstream>
#include <thread>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace exv::core::lifecycle {
namespace {

#ifdef _WIN32
const char *kCoreCandidateName = "exv.exe";
#else
const char *kCoreCandidateName = "exv";
#endif

std::string build_hello_request() {
  nlohmann::json req;
  req["action"] = "core.hello";
  req["payload_json"] = nlohmann::json::object().dump();
  req["request_id"] = "resolver-hello";
  return req.dump();
}

nlohmann::json parse_hello_response(const std::string &response_line) {
  try {
    auto parsed = nlohmann::json::parse(response_line);
    if (parsed.is_object() && parsed.value("success", false)) {
      if (parsed.contains("payload_json")) {
        auto payload = nlohmann::json::parse(
            parsed.value("payload_json", std::string("{}")));
        if (payload.is_object()) {
          return payload;
        }
      }
    }
  } catch (...) {
  }
  return {};
}

class ResolverIpcSession {
public:
  ResolverIpcSession(const CoreResolverDeps &deps, std::string ipc_path)
      : deps_(deps), ipc_path_(std::move(ipc_path)) {}

  ~ResolverIpcSession() { close(); }

  bool open() {
    if (connected_) {
      return true;
    }

    if (deps_.open_ipc_session) {
      session_owned_ = true;
      connected_ = deps_.open_ipc_session(ipc_path_);
      return connected_;
    }

    if (deps_.try_connect_ipc) {
      session_owned_ = false;
      connected_ = deps_.try_connect_ipc(ipc_path_);
      return connected_;
    }

    return false;
  }

  std::string send(const std::string &request_line) {
    if (!connected_) {
      return {};
    }

    if (session_owned_) {
      return deps_.send_ipc_session_request
                 ? deps_.send_ipc_session_request(request_line)
                 : std::string();
    }

    return deps_.send_ipc_request
               ? deps_.send_ipc_request(ipc_path_, request_line)
               : std::string();
  }

  void close() {
    if (!connected_) {
      return;
    }

    if (session_owned_) {
      if (deps_.close_ipc_session) {
        deps_.close_ipc_session();
      }
    } else if (deps_.disconnect_ipc) {
      deps_.disconnect_ipc();
    }

    connected_ = false;
  }

private:
  const CoreResolverDeps &deps_;
  std::string ipc_path_;
  bool session_owned_ = false;
  bool connected_ = false;
};

struct IpcRequestAttempt {
  bool connected = false;
  std::string response_line;
};

IpcRequestAttempt send_request_over_ipc(const CoreResolverDeps &deps,
                                        const std::string &ipc_path,
                                        const std::string &request_line) {
  ResolverIpcSession session(deps, ipc_path);
  if (!session.open()) {
    return {};
  }
  IpcRequestAttempt attempt;
  attempt.connected = true;
  attempt.response_line = session.send(request_line);
  return attempt;
}

bool contract_version_accepted(const nlohmann::json &hello_payload) {
  if (!hello_payload.is_object()) {
    return false;
  }
  const std::string contract =
      hello_payload.value("contract_version", std::string());
  return accepts_contract_version(contract);
}

bool ipc_protocol_compatible(const nlohmann::json &hello_payload) {
  if (!hello_payload.is_object()) {
    return false;
  }
  const std::string ipc_version =
      hello_payload.value("ipc_protocol_version", std::string());
  const std::string expected =
      "ipc-v" + std::to_string(exv::contracts::generated::IPC_PROTOCOL_MAJOR);
  return ipc_version == expected;
}

CoreResolveResult make_error(CoreResolveStatus status,
                             const std::string &detail) {
  CoreResolveResult result;
  result.status = status;
  result.message = core_resolve_status_code(status);
  return result;
}

CoreResolveResult make_broken(const CoreRegistryReadResult &registry_read) {
  CoreResolveResult result;
  result.status = CoreResolveStatus::CoreCommBroken;
  result.message = core_resolve_status_code(CoreResolveStatus::CoreCommBroken);
  if (registry_read.state == CoreRegistryReadState::present &&
      registry_read.snapshot.has_value()) {
    result.registry_snapshot = core_registry_to_json(*registry_read.snapshot);
  }
  return result;
}

std::optional<std::string> candidate_in_dir(const std::filesystem::path &dir) {
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec) || ec) {
    return std::nullopt;
  }
  auto candidate = dir / kCoreCandidateName;
  if (std::filesystem::exists(candidate, ec) && !ec) {
    return candidate.string();
  }
  return std::nullopt;
}

std::optional<std::string> find_in_path(const std::string &path_var,
                                        const std::string &frontend_path) {
  std::istringstream stream(path_var);
  std::string segment;
  while (std::getline(stream, segment,
#ifdef _WIN32
                      ';'
#else
                      ':'
#endif
                      )) {
    auto candidate = candidate_in_dir(std::filesystem::path(segment));
    if (candidate.has_value() &&
        !is_self_reference(*candidate, frontend_path)) {
      return candidate;
    }
  }
  return std::nullopt;
}

} // namespace

std::string core_candidate_name() { return kCoreCandidateName; }

std::string core_resolve_status_code(CoreResolveStatus status) {
  switch (status) {
  case CoreResolveStatus::ReuseExisting:
    return "";
  case CoreResolveStatus::LaunchRequired:
    return "";
  case CoreResolveStatus::CoreCommBroken:
    return "core_comm_broken";
  case CoreResolveStatus::CoreUnresponsive:
    return "core_unresponsive";
  case CoreResolveStatus::CoreProtocolMismatch:
    return "core_protocol_mismatch";
  case CoreResolveStatus::CoreNotFound:
    return "core_not_found";
  case CoreResolveStatus::CoreLaunchFailed:
    return "core_launch_failed";
  case CoreResolveStatus::CoreVersionProbeFailed:
    return "core_version_probe_failed";
  }
  return "unknown";
}

bool is_self_reference(const std::string &candidate,
                       const std::string &frontend_path) {
  if (candidate.empty() || frontend_path.empty()) {
    return false;
  }
  std::error_code ec;
  auto resolved_candidate =
      std::filesystem::canonical(candidate, ec);
  if (ec) {
    resolved_candidate = std::filesystem::path(candidate);
  }
  auto resolved_frontend =
      std::filesystem::canonical(frontend_path, ec);
  if (ec) {
    resolved_frontend = std::filesystem::path(frontend_path);
  }
  return resolved_candidate == resolved_frontend;
}

bool validate_core_version_output(const std::string &output) {
  // The core --version output must contain a machine-readable version pattern.
  // Core version line format: X.Y.Z or exv X.Y.Z
  static const std::regex version_pattern(
      R"(\b\d+\.\d+\.\d+\b)");
  return std::regex_search(output, version_pattern);
}

std::optional<std::string> find_core_candidate(
    const std::string &frontend_path,
    const std::string &env_core_path,
    const std::string &path_var) {
  // 1. EXV_CORE_PATH — interpreted as a directory
  if (!env_core_path.empty()) {
    auto candidate = candidate_in_dir(std::filesystem::path(env_core_path));
    if (candidate.has_value() &&
        !is_self_reference(*candidate, frontend_path)) {
      exv::observability::LogFacade::info(
          "Core resolver: found candidate via EXV_CORE_PATH: " + *candidate);
      return candidate;
    }
    if (candidate.has_value()) {
      exv::observability::LogFacade::info(
          "Core resolver: EXV_CORE_PATH candidate is self-reference, skipping");
    }
  }

  // 2. System PATH lookup
  if (!path_var.empty()) {
    auto candidate = find_in_path(path_var, frontend_path);
    if (candidate.has_value()) {
      exv::observability::LogFacade::info(
          "Core resolver: found candidate via PATH: " + *candidate);
      return candidate;
    }
  }

  // 3. Same directory as the current frontend executable
  if (!frontend_path.empty()) {
    std::error_code ec;
    auto parent = std::filesystem::path(frontend_path).parent_path();
    auto candidate = candidate_in_dir(parent);
    if (candidate.has_value() &&
        !is_self_reference(*candidate, frontend_path)) {
      exv::observability::LogFacade::info(
          "Core resolver: found candidate in frontend directory: " + *candidate);
      return candidate;
    }
  }

  return std::nullopt;
}

CoreResolveResult resolve_core(const CoreResolveOptions &options,
                               const CoreResolverDeps &deps) {
  const std::string state_dir = deps.get_state_dir ? deps.get_state_dir() : std::string();
  const std::string ipc_path = core_ipc_path(state_dir);

  // Step 1: Try the versioned IPC endpoint
  exv::observability::LogFacade::info(
      "Core resolver: trying IPC endpoint " + ipc_path);

  std::string request_line = build_hello_request();
  auto hello_attempt = send_request_over_ipc(deps, ipc_path, request_line);
  if (hello_attempt.connected) {
    exv::observability::LogFacade::info(
        "Core resolver: IPC endpoint available, sending core.hello");

    std::string response_line = std::move(hello_attempt.response_line);

    if (!response_line.empty()) {
      auto hello_payload = parse_hello_response(response_line);

      if (hello_payload.is_object() && !hello_payload.empty()) {
        if (!ipc_protocol_compatible(hello_payload)) {
          exv::observability::LogFacade::warn(
              "Core resolver: IPC protocol mismatch");
          return make_error(CoreResolveStatus::CoreProtocolMismatch,
                            "IPC protocol version is incompatible.");
        }
        if (!contract_version_accepted(hello_payload)) {
          exv::observability::LogFacade::warn(
              "Core resolver: contract version not accepted");
          return make_error(CoreResolveStatus::CoreProtocolMismatch,
                            "Contract version is not accepted.");
        }

        CoreResolveResult result;
        result.status = CoreResolveStatus::ReuseExisting;
        result.core_path = hello_payload.value("core_path", std::string());
        result.ipc_path = ipc_path;
        result.hello = hello_payload;

        auto registry_read = read_core_registry(core_registry_path(state_dir));
        if (registry_read.state == CoreRegistryReadState::present &&
            registry_read.snapshot.has_value()) {
          result.registry_snapshot = core_registry_to_json(*registry_read.snapshot);
        }

        exv::observability::LogFacade::info(
            "Core resolver: reused existing core (pid=" +
            std::to_string(hello_payload.value("pid", 0)) + ")");
        return result;
      }
    }

    // IPC connected but hello failed — unresponsive
    exv::observability::LogFacade::warn(
        "Core resolver: IPC connected but core.hello failed");

    // Retry hello if configured
    for (int i = 0; i < options.hello_retries; ++i) {
      std::this_thread::sleep_for(
          std::chrono::milliseconds(200));
      response_line =
          send_request_over_ipc(deps, ipc_path, request_line).response_line;
      if (!response_line.empty()) {
        auto hello_payload = parse_hello_response(response_line);
        if (hello_payload.is_object() && !hello_payload.empty()) {
          if (!ipc_protocol_compatible(hello_payload)) {
            return make_error(CoreResolveStatus::CoreProtocolMismatch,
                              "IPC protocol version is incompatible.");
          }
          if (!contract_version_accepted(hello_payload)) {
            return make_error(CoreResolveStatus::CoreProtocolMismatch,
                              "Contract version is not accepted.");
          }
          CoreResolveResult result;
          result.status = CoreResolveStatus::ReuseExisting;
          result.core_path =
              hello_payload.value("core_path", std::string());
          result.ipc_path = ipc_path;
          result.hello = hello_payload;
          return result;
        }
      }
    }

    return make_error(CoreResolveStatus::CoreUnresponsive,
                      "Core process is not responding to core.hello.");
  }

  // Step 2: IPC unavailable — inspect the versioned core lock
  exv::observability::LogFacade::info(
      "Core resolver: IPC endpoint unavailable, inspecting core lock");

  auto registry_read = read_core_registry(core_registry_path(state_dir));

  // Step 3: Check if a live core owns the lock
  if (registry_read.state == CoreRegistryReadState::present &&
      registry_read.snapshot.has_value()) {
    const auto &snap = *registry_read.snapshot;
    if (snap.pid > 0 && deps.is_pid_alive && deps.is_pid_alive(snap.pid)) {
      // Live owner holds the lock but IPC is unavailable → core_comm_broken
      exv::observability::LogFacade::warn(
          "Core resolver: live core (pid=" + std::to_string(snap.pid) +
          ") holds lock but IPC is broken");
      return make_broken(registry_read);
    }
  }

  // Step 4: No live core — discover and start a core executable
  exv::observability::LogFacade::info(
      "Core resolver: no live core, discovering core executable");

  const std::string frontend_path =
      deps.get_frontend_executable_path
          ? deps.get_frontend_executable_path()
          : std::string();

  std::optional<std::string> candidate;
  if (!options.preferred_core_path.empty()) {
    std::error_code ec;
    if (std::filesystem::exists(options.preferred_core_path, ec) && !ec &&
        !is_self_reference(options.preferred_core_path, frontend_path)) {
      exv::observability::LogFacade::info(
          "Core resolver: using preferred core path: " +
          options.preferred_core_path);
      candidate = options.preferred_core_path;
    } else {
      exv::observability::LogFacade::warn(
          "Core resolver: preferred core path is unavailable or invalid: " +
          options.preferred_core_path);
    }
  }

  if (!candidate.has_value()) {
    const std::string env_core_path =
        deps.get_env_var ? deps.get_env_var("EXV_CORE_PATH") : std::string();
    const std::string path_var =
        deps.get_env_var ? deps.get_env_var("PATH") : std::string();
    candidate = find_core_candidate(frontend_path, env_core_path, path_var);
  }

  if (!candidate.has_value()) {
    exv::observability::LogFacade::warn(
        "Core resolver: no core executable found");
    return make_error(CoreResolveStatus::CoreNotFound,
                      "No core executable found.");
  }

  // Step 5: Validate candidate with --version probe
  exv::observability::LogFacade::info(
      "Core resolver: probing candidate " + *candidate);

  std::string version_cmd =
      exv::platform::shell_quote(*candidate) + " --version";
  std::string version_output =
      deps.run_command_output ? deps.run_command_output(version_cmd)
                              : std::string();

  if (!validate_core_version_output(version_output)) {
    exv::observability::LogFacade::warn(
        "Core resolver: version probe failed for " + *candidate);
    return make_error(CoreResolveStatus::CoreVersionProbeFailed,
                      "Core candidate version probe failed: " + *candidate);
  }

  // Step 6: Launch core
  exv::observability::LogFacade::info(
      "Core resolver: launching core " + *candidate);

  const std::string home_dir =
      deps.get_home_dir ? deps.get_home_dir() : std::string();
  if (!deps.launch_core || !deps.launch_core(*candidate, state_dir, home_dir)) {
    exv::observability::LogFacade::error(
        "Core resolver: core launch failed for " + *candidate);
    return make_error(CoreResolveStatus::CoreLaunchFailed,
                      "Failed to launch core process: " + *candidate);
  }

  // Step 7: Wait for core to become available, then send core.hello
  const auto start = std::chrono::steady_clock::now();
  const auto deadline = start + options.hello_timeout;

  while (std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string request_line = build_hello_request();
    auto launched_hello_attempt =
        send_request_over_ipc(deps, ipc_path, request_line);
    if (!launched_hello_attempt.connected) {
      continue;
    }

    std::string response_line = std::move(launched_hello_attempt.response_line);

    if (response_line.empty()) {
      continue;
    }

    auto hello_payload = parse_hello_response(response_line);
    if (!hello_payload.is_object() || hello_payload.empty()) {
      continue;
    }

    if (!ipc_protocol_compatible(hello_payload)) {
      return make_error(CoreResolveStatus::CoreProtocolMismatch,
                        "IPC protocol version is incompatible after launch.");
    }
    if (!contract_version_accepted(hello_payload)) {
      return make_error(CoreResolveStatus::CoreProtocolMismatch,
                        "Contract version is not accepted after launch.");
    }

    CoreResolveResult result;
    result.status = CoreResolveStatus::LaunchRequired;
    result.core_path = hello_payload.value("core_path", std::string());
    result.ipc_path = ipc_path;
    result.hello = hello_payload;

    auto new_registry =
        read_core_registry(core_registry_path(state_dir));
    if (new_registry.state == CoreRegistryReadState::present &&
        new_registry.snapshot.has_value()) {
      result.registry_snapshot = core_registry_to_json(*new_registry.snapshot);
    }

    exv::observability::LogFacade::info(
        "Core resolver: started and connected to new core (pid=" +
        std::to_string(hello_payload.value("pid", 0)) + ")");
    return result;
  }

  // Core was launched but never became responsive
  exv::observability::LogFacade::error(
      "Core resolver: launched core but it did not become responsive");

  // Check if the registry now shows a live core — might be comm_broken
  auto post_registry =
      read_core_registry(core_registry_path(state_dir));
  if (post_registry.state == CoreRegistryReadState::present &&
      post_registry.snapshot.has_value() &&
      post_registry.snapshot->pid > 0 &&
      deps.is_pid_alive && deps.is_pid_alive(post_registry.snapshot->pid)) {
    return make_broken(post_registry);
  }

  return make_error(CoreResolveStatus::CoreUnresponsive,
                    "Core process was launched but did not respond within "
                    "the timeout period.");
}

} // namespace exv::core::lifecycle
