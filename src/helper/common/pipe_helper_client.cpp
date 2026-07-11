#include "pipe_helper_client.hpp"
#include "helper_protocol.hpp"
#include "observability/log_facade.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#endif

namespace exv::helper {

using json = nlohmann::json;

namespace {

std::string helper_op_name(HelperOp op) {
    switch (op) {
    case HelperOp::Hello:
        return "Hello";
    case HelperOp::StartSession:
        return "StartSession";
    case HelperOp::PrepareTunnelDevice:
        return "PrepareTunnelDevice";
    case HelperOp::ApplyTunnelConfig:
        return "ApplyTunnelConfig";
    case HelperOp::Heartbeat:
        return "Heartbeat";
    case HelperOp::Cleanup:
        return "Cleanup";
    case HelperOp::GetSnapshot:
        return "GetSnapshot";
    case HelperOp::Shutdown:
        return "Shutdown";
    case HelperOp::Inspect:
        return "Inspect";
    case HelperOp::AcquireCoreLease:
        return "AcquireCoreLease";
    case HelperOp::KeepAlive:
        return "KeepAlive";
    case HelperOp::ReleaseCoreLease:
        return "ReleaseCoreLease";
    }
    return "Unknown";
}

void log_helper_client_event(
    const std::string& level,
    const std::string& code,
    const std::string& message,
    std::vector<std::pair<std::string, std::string>> fields = {}) {
    exv::observability::LogFacade::event(level, "helper", code, message,
                                         std::move(fields));
}

void log_helper_rpc_failure(const PipeClientConfig& config,
                            HelperOp op,
                            const std::string& error_code,
                            const std::string& error_message,
                            bool connected) {
    log_helper_client_event(
        "WARN", "helper.rpc.failed", "Helper RPC request failed",
        {{"op", helper_op_name(op)},
         {"endpoint", config.pipe_path},
         {"error_code", error_code.empty() ? "unknown" : error_code},
         {"error_message", error_message},
         {"connected", connected ? "true" : "false"}});
}

#ifdef _WIN32
bool is_windows_named_pipe_path(const std::string& path) {
    return path.rfind("\\\\.\\pipe\\", 0) == 0 ||
           path.rfind("\\\\?\\pipe\\", 0) == 0;
}
#endif

} // namespace

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

PipeHelperClient::PipeHelperClient(const PipeClientConfig& config)
    : config_(config) {}

PipeHelperClient::~PipeHelperClient() {
    disconnect();
}

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

bool PipeHelperClient::connect() {
    if (connected_)
        return true;

#ifdef _WIN32
    if (!is_windows_named_pipe_path(config_.pipe_path)) {
        log_helper_client_event(
            "WARN", "helper.pipe.invalid_endpoint",
            "Helper pipe endpoint is not a Windows named pipe",
            {{"endpoint", config_.pipe_path}});
        return false;
    }

    const DWORD start_tick = GetTickCount();
    const DWORD deadline = start_tick + static_cast<DWORD>(config_.connect_timeout_ms);
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    DWORD last_error = ERROR_SUCCESS;

    while (GetTickCount() < deadline) {
        hPipe = CreateFileA(
            config_.pipe_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        last_error = GetLastError();
        if (last_error == ERROR_PIPE_BUSY) {
            WaitNamedPipeA(config_.pipe_path.c_str(), 250);
        } else if (last_error == ERROR_FILE_NOT_FOUND) {
            // Pipe not yet available; retry with shorter interval for faster startup
            DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= static_cast<DWORD>(config_.connect_timeout_ms))
                break;
            Sleep(50);  // More aggressive retry interval (was 100ms)
        } else {
            break;
        }
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        log_helper_client_event(
            "WARN", "helper.pipe.connect_failed",
            "Failed to connect to helper pipe",
            {{"endpoint", config_.pipe_path},
             {"win32_error", std::to_string(last_error)},
             {"timeout_ms", std::to_string(config_.connect_timeout_ms)}});
        return false;
    }

    // Set pipe to byte-read mode (matches server's PIPE_READMODE_BYTE)
    DWORD mode = PIPE_READMODE_BYTE;
    if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
        const DWORD err = GetLastError();
        log_helper_client_event(
            "WARN", "helper.pipe.mode_failed",
            "Failed to set helper pipe read mode",
            {{"endpoint", config_.pipe_path},
             {"win32_error", std::to_string(err)}});
    }

    pipe_handle_ = static_cast<void*>(hPipe);
#else
    socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        log_helper_client_event(
            "WARN", "helper.pipe.socket_failed",
            "Failed to create helper Unix socket",
            {{"endpoint", config_.pipe_path},
             {"errno", std::to_string(errno)}});
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
                  config_.pipe_path.c_str());

    if (::connect(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        const int saved_errno = errno;
        ::close(socket_fd_);
        socket_fd_ = -1;
        log_helper_client_event(
            "WARN", "helper.pipe.connect_failed",
            "Failed to connect to helper Unix socket",
            {{"endpoint", config_.pipe_path},
             {"errno", std::to_string(saved_errno)},
             {"timeout_ms", std::to_string(config_.connect_timeout_ms)}});
        return false;
    }
#endif

    connected_ = true;
    return true;
}

void PipeHelperClient::disconnect() {
    if (!connected_)
        return;
    connected_ = false;

#ifdef _WIN32
    if (pipe_handle_ && pipe_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(static_cast<HANDLE>(pipe_handle_));
        pipe_handle_ = nullptr;
    }
#else
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
#endif

    if (disconnect_cb_)
        disconnect_cb_();
}

bool PipeHelperClient::is_connected() const {
    return connected_;
}

void PipeHelperClient::set_disconnect_callback(DisconnectCallback cb) {
    disconnect_cb_ = std::move(cb);
}

// ---------------------------------------------------------------------------
// Low-level transport
// ---------------------------------------------------------------------------

bool PipeHelperClient::send_raw(const std::string& data) {
    if (!connected_)
        return false;

#ifdef _WIN32
    HANDLE hPipe = static_cast<HANDLE>(pipe_handle_);
    DWORD bytes_written = 0;
    if (!WriteFile(hPipe, data.c_str(), static_cast<DWORD>(data.size()),
                   &bytes_written, NULL) ||
        bytes_written != data.size()) {
        const DWORD err = GetLastError();
        log_helper_client_event(
            "WARN", "helper.pipe.write_failed",
            "Failed to write helper pipe request",
            {{"endpoint", config_.pipe_path},
             {"win32_error", std::to_string(err)},
             {"bytes_expected", std::to_string(data.size())},
             {"bytes_written", std::to_string(bytes_written)}});
        disconnect();
        return false;
    }
    if (!FlushFileBuffers(hPipe)) {
        const DWORD err = GetLastError();
        log_helper_client_event(
            "WARN", "helper.pipe.flush_failed",
            "Failed to flush helper pipe request",
            {{"endpoint", config_.pipe_path},
             {"win32_error", std::to_string(err)}});
        disconnect();
        return false;
    }
    return true;
#else
    const char* ptr = data.c_str();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t written = ::write(socket_fd_, ptr, remaining);
        if (written <= 0) {
            const int saved_errno = errno;
            log_helper_client_event(
                "WARN", "helper.pipe.write_failed",
                "Failed to write helper socket request",
                {{"endpoint", config_.pipe_path},
                 {"errno", std::to_string(saved_errno)},
                 {"bytes_remaining", std::to_string(remaining)}});
            disconnect();
            return false;
        }
        ptr += written;
        remaining -= static_cast<size_t>(written);
    }
    return true;
#endif
}

std::string PipeHelperClient::recv_raw() {
    if (!connected_)
        return {};

    std::string raw;
#ifdef _WIN32
    HANDLE hPipe = static_cast<HANDLE>(pipe_handle_);
    char buffer[4096];
    DWORD bytes_read = 0;
    const DWORD timeout_ms = static_cast<DWORD>(
        std::max(config_.response_timeout_ms, 1));
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;

    while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(hPipe, NULL, 0, NULL, &available, NULL)) {
            DWORD err = GetLastError();
            log_helper_client_event(
                "WARN", "helper.pipe.peek_failed",
                "Failed while waiting for helper pipe response",
                {{"endpoint", config_.pipe_path},
                 {"win32_error", std::to_string(err)}});
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                disconnect();
            }
            break;
        }
        if (available == 0) {
            if (GetTickCount64() >= deadline) {
                log_helper_client_event(
                    "WARN", "helper.pipe.response_timeout",
                    "Timed out waiting for helper pipe response",
                    {{"endpoint", config_.pipe_path},
                     {"timeout_ms", std::to_string(timeout_ms)}});
                disconnect();
                break;
            }
            Sleep(10);
            continue;
        }

        BOOL ok = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytes_read, NULL);
        if (!ok || bytes_read == 0) {
            // Connection lost or pipe closed
            DWORD err = GetLastError();
            log_helper_client_event(
                "WARN", "helper.pipe.read_failed",
                "Failed to read helper pipe response",
                {{"endpoint", config_.pipe_path},
                 {"win32_error", std::to_string(err)},
                 {"bytes_read", std::to_string(bytes_read)}});
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                disconnect();
            }
            break;
        }
        raw.append(buffer, bytes_read);
        if (raw.find('\n') != std::string::npos)
            break;
    }
#else
    char buffer[4096];
    ssize_t n = 0;
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(std::max(config_.response_timeout_ms, 1));
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            log_helper_client_event(
                "WARN", "helper.pipe.response_timeout",
                "Timed out waiting for helper socket response",
                {{"endpoint", config_.pipe_path},
                 {"timeout_ms", std::to_string(config_.response_timeout_ms)}});
            disconnect();
            break;
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        pollfd pfd{};
        pfd.fd = socket_fd_;
        pfd.events = POLLIN;
        int ready = ::poll(&pfd, 1, static_cast<int>(remaining.count()));
        if (ready <= 0) {
            const int saved_errno = errno;
            log_helper_client_event(
                "WARN",
                ready == 0 ? "helper.pipe.response_timeout"
                           : "helper.pipe.poll_failed",
                ready == 0 ? "Timed out waiting for helper socket response"
                           : "Failed while polling helper socket response",
                {{"endpoint", config_.pipe_path},
                 {"errno", std::to_string(saved_errno)},
                 {"timeout_ms", std::to_string(config_.response_timeout_ms)}});
            disconnect();
            break;
        }
        n = ::read(socket_fd_, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            // EOF or error -- peer disconnected
            const int saved_errno = errno;
            log_helper_client_event(
                "WARN", "helper.pipe.read_failed",
                "Failed to read helper socket response",
                {{"endpoint", config_.pipe_path},
                 {"errno", std::to_string(saved_errno)},
                 {"bytes_read", std::to_string(n)}});
            if (n == 0 || (saved_errno != EINTR && saved_errno != EAGAIN))
                disconnect();
            break;
        }
        buffer[n] = '\0';
        raw.append(buffer, static_cast<size_t>(n));
        if (raw.find('\n') != std::string::npos)
            break;
    }
#endif

    // Strip trailing newline
    if (!raw.empty() && raw.back() == '\n')
        raw.pop_back();
    if (!raw.empty() && raw.back() == '\r')
        raw.pop_back();

    return raw;
}

// ---------------------------------------------------------------------------
// Helper envelope: send_request
// ---------------------------------------------------------------------------

HelperResponse PipeHelperClient::send_request(HelperOp op,
                                               const json& payload) {
    std::lock_guard<std::mutex> request_lock(request_mutex_);

    HelperResponse resp{};
    resp.op = op;

    if (!connected_) {
        resp.success = false;
        resp.error_code = "not_connected";
        resp.error_message = "PipeHelperClient is not connected";
        log_helper_rpc_failure(config_, op, resp.error_code, resp.error_message,
                               connected_);
        return resp;
    }

    // Build helper envelope
    HelperRequest req;
    req.op = op;
    req.payload_json = payload.dump();
    json envelope = req;

    std::string wire = envelope.dump();
    wire.push_back('\n');

    if (!send_raw(wire)) {
        resp.success = false;
        resp.error_code = "send_failed";
        resp.error_message = "Failed to send request over pipe";
        log_helper_rpc_failure(config_, op, resp.error_code, resp.error_message,
                               connected_);
        return resp;
    }

    std::string raw_response = recv_raw();
    if (raw_response.empty()) {
        resp.success = false;
        resp.error_code = "recv_failed";
        resp.error_message = "Empty response from helper daemon";
        log_helper_rpc_failure(config_, op, resp.error_code, resp.error_message,
                               connected_);
        return resp;
    }

    try {
        json resp_json = json::parse(raw_response);
        resp = helper_response_from_json(resp_json);
    } catch (const std::exception& e) {
        resp.success = false;
        resp.error_code = "parse_error";
        resp.error_message = std::string("Failed to parse helper response: ") + e.what();
    }

    // Guard against a well-formed envelope that reports success but carries an
    // empty payload_json. Each protocol method does an unguarded
    // json::parse(resp.payload_json) on its success branch; an empty payload
    // there throws nlohmann::parse_error.101 which propagates as an opaque
    // "parse_error" to the UI (seen during service install: the envelope
    // arrived but the payload was lost to a truncated/partial response frame).
    // Convert this into a controlled failure so callers get a clear code
    // instead of a raw exception.
    if (resp.success && resp.payload_json.empty()) {
        resp.success = false;
        resp.error_code = "helper_response_empty";
        resp.error_message =
            "Helper acknowledged the request but returned an empty response payload";
    }

    if (!resp.success) {
        log_helper_rpc_failure(config_, op, resp.error_code, resp.error_message,
                               connected_);
    }

    return resp;
}

// ---------------------------------------------------------------------------
// Helper protocol methods
// ---------------------------------------------------------------------------

HelloResponse PipeHelperClient::hello(const HelloRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::Hello, payload);
    if (!resp.success) {
        HelloResponse hr;
        return hr;
    }
    return hello_response_from_json(json::parse(resp.payload_json));
}

StartSessionResponse PipeHelperClient::start_session(const StartSessionRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::StartSession, payload);
    if (!resp.success) {
        StartSessionResponse sr;
        return sr;
    }
    return start_session_response_from_json(json::parse(resp.payload_json));
}

PrepareTunnelDeviceResponse PipeHelperClient::prepare_tunnel_device(
    const PrepareTunnelDeviceRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::PrepareTunnelDevice, payload);
    if (!resp.success) {
        PrepareTunnelDeviceResponse pr;
        pr.error_code = resp.error_code;
        pr.error_message = resp.error_message;
        return pr;
    }
    return prepare_tunnel_device_response_from_json(json::parse(resp.payload_json));
}

ApplyTunnelConfigResponse PipeHelperClient::apply_tunnel_config(
    const ApplyTunnelConfigRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::ApplyTunnelConfig, payload);
    if (!resp.success) {
        if (!resp.payload_json.empty()) {
            try {
                auto parsed = apply_tunnel_config_response_from_json(
                    json::parse(resp.payload_json));
                if (!parsed.error_code.empty() ||
                    !parsed.error_message.empty() ||
                    !parsed.error_target.empty() ||
                    parsed.system_error != 0) {
                    return parsed;
                }
            } catch (...) {
            }
        }
        ApplyTunnelConfigResponse ar;
        ar.error_code = resp.error_code;
        ar.error_message = resp.error_message;
        return ar;
    }
    return apply_tunnel_config_response_from_json(json::parse(resp.payload_json));
}

HeartbeatResponse PipeHelperClient::heartbeat(const HeartbeatRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::Heartbeat, payload);
    if (!resp.success) {
        HeartbeatResponse hr;
        hr.ok = false;
        return hr;
    }
    return heartbeat_response_from_json(json::parse(resp.payload_json));
}

CleanupResponse PipeHelperClient::cleanup(const CleanupRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::Cleanup, payload);
    if (!resp.success) {
        CleanupResponse cr;
        cr.success = false;
        cr.errors.push_back(resp.error_message);
        return cr;
    }
    return cleanup_response_from_json(json::parse(resp.payload_json));
}

GetSnapshotResponse PipeHelperClient::get_snapshot(const GetSnapshotRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::GetSnapshot, payload);
    if (!resp.success) {
        return GetSnapshotResponse{};
    }
    return get_snapshot_response_from_json(json::parse(resp.payload_json));
}

ShutdownResponse PipeHelperClient::shutdown(const ShutdownRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::Shutdown, payload);
    if (!resp.success) {
        exv::observability::LogFacade::warn(
            "PipeHelperClient: Shutdown failed code=" + resp.error_code +
            " message=" + resp.error_message);
        ShutdownResponse sr;
        sr.cleanup_success = false;
        if (!resp.payload_json.empty()) {
            try {
                sr = shutdown_response_from_json(json::parse(resp.payload_json));
            } catch (...) {
            }
        }
        sr.errors.push_back(resp.error_message);
        return sr;
    }
    return shutdown_response_from_json(json::parse(resp.payload_json));
}

InspectResponse PipeHelperClient::inspect(const InspectRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::Inspect, payload);
    if (!resp.success) {
        return InspectResponse{};
    }
    return inspect_response_from_json(json::parse(resp.payload_json));
}

AcquireCoreLeaseResponse PipeHelperClient::acquire_core_lease(
    const AcquireCoreLeaseRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::AcquireCoreLease, payload);
    if (!resp.success) {
        exv::observability::LogFacade::warn(
            "PipeHelperClient: AcquireCoreLease failed code=" +
            resp.error_code + " message=" + resp.error_message);
        AcquireCoreLeaseResponse acr;
        acr.accepted = false;
        acr.error_code = resp.error_code;
        acr.error_message = resp.error_message;
        return acr;
    }
    return acquire_core_lease_response_from_json(json::parse(resp.payload_json));
}

KeepAliveResponse PipeHelperClient::keep_alive(const KeepAliveRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::KeepAlive, payload);
    if (!resp.success) {
        KeepAliveResponse kr;
        kr.ok = false;
        kr.warning = resp.error_message;
        return kr;
    }
    return keep_alive_response_from_json(json::parse(resp.payload_json));
}

ReleaseCoreLeaseResponse PipeHelperClient::release_core_lease(
    const ReleaseCoreLeaseRequest& req) {
    json payload = req;
    auto resp = send_request(HelperOp::ReleaseCoreLease, payload);
    if (!resp.success) {
        exv::observability::LogFacade::warn(
            "PipeHelperClient: ReleaseCoreLease failed code=" +
            resp.error_code + " message=" + resp.error_message);
        return ReleaseCoreLeaseResponse{};
    }
    return release_core_lease_response_from_json(json::parse(resp.payload_json));
}
} // namespace exv::helper
