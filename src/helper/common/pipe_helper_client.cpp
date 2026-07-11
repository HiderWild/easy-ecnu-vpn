#include "pipe_helper_client.hpp"
#include "helper_protocol.hpp"
#include "observability/log_facade.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
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

#ifdef _WIN32
namespace {

bool is_windows_named_pipe_path(const std::string& path) {
    return path.rfind("\\\\.\\pipe\\", 0) == 0 ||
           path.rfind("\\\\?\\pipe\\", 0) == 0;
}

} // namespace
#endif

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
        return false;
    }

    const DWORD start_tick = GetTickCount();
    const DWORD deadline = start_tick + static_cast<DWORD>(config_.connect_timeout_ms);
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    while (GetTickCount() < deadline) {
        hPipe = CreateFileA(
            config_.pipe_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            WaitNamedPipeA(config_.pipe_path.c_str(), 250);
        } else if (err == ERROR_FILE_NOT_FOUND) {
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
        return false;
    }

    // Set pipe to byte-read mode (matches server's PIPE_READMODE_BYTE)
    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

    pipe_handle_ = static_cast<void*>(hPipe);
#else
    socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd_ < 0)
        return false;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
                  config_.pipe_path.c_str());

    if (::connect(socket_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
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
        disconnect();
        return false;
    }
    FlushFileBuffers(hPipe);
    return true;
#else
    const char* ptr = data.c_str();
    size_t remaining = data.size();
    while (remaining > 0) {
        ssize_t written = ::write(socket_fd_, ptr, remaining);
        if (written <= 0) {
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
            if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                disconnect();
            }
            break;
        }
        if (available == 0) {
            if (GetTickCount64() >= deadline) {
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
            disconnect();
            break;
        }
        n = ::read(socket_fd_, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            // EOF or error -- peer disconnected
            if (n == 0 || (errno != EINTR && errno != EAGAIN))
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
        return resp;
    }

    std::string raw_response = recv_raw();
    if (raw_response.empty()) {
        resp.success = false;
        resp.error_code = "recv_failed";
        resp.error_message = "Empty response from helper daemon";
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
        return AcquireCoreLeaseResponse{};
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
