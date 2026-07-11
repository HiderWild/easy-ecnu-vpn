#include "app/ui_shell/core_rpc_client.hpp"

#include "cli/pipe_client.hpp"
#include "platform/common/core_resolver.hpp"
#include "platform/common/process_utils.hpp"
#include "runtime/runtime_context.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#endif

#include <charconv>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <system_error>
#include <thread>
#include <utility>

namespace exv::ui_shell {
namespace {

int request_id_to_int(const std::string &request_id) {
  if (request_id.empty()) {
    return 0;
  }
  int value = 0;
  const char *begin = request_id.data();
  const char *end = begin + request_id.size();
  const auto result = std::from_chars(begin, end, value);
  if (result.ec != std::errc{} || result.ptr != end) {
    return 0;
  }
  return value;
}

std::string payload_json_to_string(const nlohmann::json &value) {
  if (value.is_string()) {
    return value.get<std::string>();
  }
  return value.dump();
}

nlohmann::json payload_json_to_value(const std::string &payload_json) {
  if (payload_json.empty()) {
    return nlohmann::json::object();
  }
  return nlohmann::json::parse(payload_json);
}

CoreRpcResponse transport_error(const CoreRpcRequest &request,
                                std::string code,
                                std::string message) {
  CoreRpcResponse response;
  response.id = request_id_to_int(request.request_id);
  response.request_id = request.request_id;
  response.ok = false;
  response.code = std::move(code);
  response.message = std::move(message);
  return response;
}

std::future<CoreRpcResponse> ready_future(CoreRpcResponse response) {
  std::promise<CoreRpcResponse> promise;
  auto future = promise.get_future();
  promise.set_value(std::move(response));
  return future;
}

std::string response_key(const CoreRpcResponse &response) {
  if (!response.request_id.empty()) {
    return response.request_id;
  }
  return std::to_string(response.id);
}

} // namespace

CoreRpcClient::CoreRpcClient(CoreRpcTransport &transport,
                             CoreRpcWireMode wire_mode)
    : transport_(transport), wire_mode_(wire_mode) {}

CoreRpcClient::~CoreRpcClient() {
  shutdown();
}

CoreRpcResponse CoreRpcClient::invoke(const CoreRpcRequest &request) {
  return invoke_async(request).get();
}

std::future<CoreRpcResponse> CoreRpcClient::invoke_async(CoreRpcRequest request) {
  std::string request_line;
  try {
    request_line = wire_mode_ == CoreRpcWireMode::Native
                       ? serialize_core_rpc_request(request)
                       : serialize_desktop_rpc_request(request);
  } catch (const nlohmann::json::exception &error) {
    return ready_future(transport_error(request, "protocol_error", error.what()));
  }

  const std::string key = request.request_id;
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto unmatched = unmatched_responses_.find(key);
    if (unmatched != unmatched_responses_.end()) {
      auto response = std::move(unmatched->second);
      unmatched_responses_.erase(unmatched);
      return ready_future(std::move(response));
    }
  }

  auto promise = std::make_shared<std::promise<CoreRpcResponse>>();
  auto future = promise->get_future();
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    if (shutting_down_) {
      promise->set_value(transport_error(request, "transport_closed",
                                         "Core RPC transport is closed"));
      return future;
    }
    pending_[key] = promise;
  }

  {
    std::lock_guard<std::mutex> lock(write_mutex_);
    if (!transport_.write_line(request_line)) {
      {
        std::lock_guard<std::mutex> pending_lock(pending_mutex_);
        pending_.erase(key);
      }
      promise->set_value(transport_error(request, "transport_closed",
                                         "Core RPC transport is closed"));
      return future;
    }
  }

  ensure_reader_started();
  return future;
}

void CoreRpcClient::set_event_handler(CoreRpcEventHandler handler) {
  std::deque<CoreRpcEvent> pending;
  {
    std::lock_guard<std::mutex> lock(event_mutex_);
    event_handler_ = std::move(handler);
    if (event_handler_) {
      pending.swap(pending_events_);
    }
  }
  for (const auto &event : pending) {
    CoreRpcEventHandler current;
    {
      std::lock_guard<std::mutex> lock(event_mutex_);
      current = event_handler_;
    }
    if (current) {
      current(event);
    }
  }
}

void CoreRpcClient::pump_events() {
  std::unique_lock<std::mutex> read_lock(read_mutex_, std::try_to_lock);
  if (!read_lock.owns_lock()) {
    return;
  }
  for (;;) {
    std::string line;
    if (!transport_.read_available_line(line)) {
      return;
    }

    try {
      const auto parsed = nlohmann::json::parse(line);
      if (parsed.is_object() && parsed.contains("event")) {
        auto event = parse_core_rpc_event_line(line);
        CoreRpcEventHandler handler;
        {
          std::lock_guard<std::mutex> lock(event_mutex_);
          handler = event_handler_;
          if (!handler && event.event == "quick-start-request") {
            pending_events_.push_back(event);
          }
        }
        if (handler) {
          handler(event);
        }
        continue;
      }
      buffered_response_lines_.push_back(line);
    } catch (const nlohmann::json::exception &) {
      buffered_response_lines_.push_back(line);
    }
  }
}

void CoreRpcClient::shutdown() {
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    if (shutting_down_) {
      return;
    }
    shutting_down_ = true;
  }

  CoreRpcResponse response;
  response.ok = false;
  response.code = "transport_closed";
  response.message = "Core RPC transport is closed";
  resolve_all_pending(response);

  transport_.close();

  if (reader_thread_.joinable()) {
    reader_thread_.join();
  }
}

void CoreRpcClient::ensure_reader_started() {
  std::lock_guard<std::mutex> lock(pending_mutex_);
  if (reader_started_ || shutting_down_) {
    return;
  }
  reader_started_ = true;
  reader_thread_ = std::thread([this] { reader_loop(); });
}

void CoreRpcClient::reader_loop() {
  for (;;) {
    std::string response_line;
    {
      std::lock_guard<std::mutex> read_lock(read_mutex_);
      if (!buffered_response_lines_.empty()) {
        response_line = buffered_response_lines_.front();
        buffered_response_lines_.pop_front();
      } else if (!transport_.read_line(response_line)) {
        CoreRpcResponse response;
        response.ok = false;
        response.code = "transport_closed";
        response.message = "Core RPC transport is closed";
        resolve_all_pending(response);
        return;
      }
    }

    try {
      const auto parsed = nlohmann::json::parse(response_line);
      if (parsed.is_object() && parsed.contains("event")) {
        auto event = parse_core_rpc_event_line(response_line);
        CoreRpcEventHandler handler;
        {
          std::lock_guard<std::mutex> lock(event_mutex_);
          handler = event_handler_;
          if (!handler && event.event == "quick-start-request") {
            pending_events_.push_back(event);
          }
        }
        if (handler) {
          handler(event);
        }
        continue;
      }
      resolve_pending(parse_core_rpc_line(response_line));
    } catch (const nlohmann::json::exception &error) {
      CoreRpcResponse response;
      response.ok = false;
      response.code = "protocol_error";
      response.message = error.what();
      resolve_all_pending(response);
      return;
    }
  }
}

void CoreRpcClient::resolve_pending(CoreRpcResponse response) {
  std::shared_ptr<std::promise<CoreRpcResponse>> promise;
  const std::string key = response_key(response);
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    auto it = pending_.find(key);
    if (it == pending_.end()) {
      unmatched_responses_[key] = std::move(response);
      return;
    }
    promise = std::move(it->second);
    pending_.erase(it);
  }
  promise->set_value(std::move(response));
}

void CoreRpcClient::resolve_all_pending(CoreRpcResponse response) {
  std::map<std::string, std::shared_ptr<std::promise<CoreRpcResponse>>> pending;
  {
    std::lock_guard<std::mutex> lock(pending_mutex_);
    pending.swap(pending_);
  }
  for (auto &entry : pending) {
    CoreRpcResponse copy = response;
    copy.request_id = entry.first;
    copy.id = request_id_to_int(entry.first);
    entry.second->set_value(std::move(copy));
  }
}

std::string serialize_core_rpc_request(const CoreRpcRequest &request) {
  nlohmann::ordered_json out;
  out["action"] = request.action;
  out["payload_json"] = request.payload_json.empty()
                            ? nlohmann::json::object().dump()
                            : request.payload_json;
  out["request_id"] = request.request_id;
  return out.dump();
}

std::string serialize_desktop_rpc_request(const CoreRpcRequest &request) {
  nlohmann::ordered_json out;
  out["id"] = request_id_to_int(request.request_id);
  out["action"] = request.action;
  out["payload"] = payload_json_to_value(request.payload_json);
  return out.dump();
}

CoreRpcResponse parse_core_rpc_line(const std::string &line) {
  const auto parsed = nlohmann::json::parse(line);
  CoreRpcResponse out;

  if (parsed.contains("success")) {
    out.request_id = parsed.at("request_id").get<std::string>();
    out.id = request_id_to_int(out.request_id);
    out.ok = parsed.value("success", false);
    if (out.ok && parsed.contains("payload_json")) {
      out.data_json = payload_json_to_string(parsed.at("payload_json"));
    }
    out.code = parsed.value("error_code", "");
    out.message = parsed.value("error_message", "");
    return out;
  }

  out.id = parsed.value("id", 0);
  out.request_id = std::to_string(out.id);
  out.ok = parsed.value("ok", false);
  if (parsed.contains("data")) {
    out.data_json = parsed.at("data").dump();
  }
  out.code = parsed.value("code", "");
  out.message = parsed.value("message", "");
  return out;
}

CoreRpcEvent parse_core_rpc_event_line(const std::string &line) {
  const auto parsed = nlohmann::json::parse(line);
  CoreRpcEvent out;
  out.event = parsed.value("event", "");
  out.data_json = parsed.contains("data") ? parsed.at("data").dump()
                                      : nlohmann::json::object().dump();
  return out;
}

exv::core::lifecycle::CoreResolverDeps make_pipe_resolver_deps() {
  using namespace exv::core::lifecycle;
  CoreResolverDeps deps;
  auto ipc_session = std::make_shared<exv::cli::PipeClient>();

  deps.open_ipc_session = [ipc_session](const std::string &ipc_path) {
    if (ipc_session->is_connected()) {
      return true;
    }
    return ipc_session->connect(ipc_path);
  };

  deps.send_ipc_session_request = [ipc_session](
                                      const std::string &request_line) {
    std::string response = ipc_session->send_request(request_line);
    if (response.empty()) {
      ipc_session->disconnect();
    }
    return response;
  };

  deps.close_ipc_session = [ipc_session] {
    ipc_session->disconnect();
  };

  deps.try_connect_ipc = [](const std::string &ipc_path) {
    return exv::cli::PipeClient::probe(ipc_path);
  };

  deps.send_ipc_request = [](const std::string &ipc_path,
                             const std::string &request_line) -> std::string {
    exv::cli::PipeClient client;
    if (!client.connect(ipc_path)) {
      return {};
    }
    std::string response = client.send_request(request_line);
    client.disconnect();
    return response;
  };

  deps.disconnect_ipc = [] {};

  deps.is_pid_alive = [](int pid) -> bool {
#ifdef _WIN32
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                           FALSE, static_cast<DWORD>(pid));
    if (!h) return false;
    DWORD code = 0;
    if (!GetExitCodeProcess(h, &code) || code != STILL_ACTIVE) {
      CloseHandle(h);
      return false;
    }
    CloseHandle(h);
    return true;
#else
    return kill(pid, 0) == 0;
#endif
  };

  deps.get_frontend_executable_path = []() {
    return exv::platform::get_executable_path();
  };

  deps.run_command_output = [](const std::string &cmd) {
    return exv::platform::run_command_output(cmd);
  };

  deps.get_state_dir = []() {
    return exv::runtime::paths().state_dir;
  };

  deps.get_home_dir = []() {
    return exv::runtime::paths().home;
  };

  deps.get_env_var = [](const std::string &name) -> std::string {
    const char *val = std::getenv(name.c_str());
    return val ? std::string(val) : std::string();
  };

  return deps;
}

} // namespace exv::ui_shell
