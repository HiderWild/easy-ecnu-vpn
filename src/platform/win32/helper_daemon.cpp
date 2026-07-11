#include "helper/helper_ipc.hpp"
#include "observability/log_facade.hpp"

#ifdef _WIN32
#include <windows.h>
#include <sddl.h>
#include <string>
#include <vector>
#endif

namespace exv {
namespace helper {

class WinIpcServer : public IpcServer {
#ifdef _WIN32
  HANDLE hPipe_ = INVALID_HANDLE_VALUE;
#endif
  unsigned int peer_uid_ = 0;
  unsigned int peer_gid_ = 0;
  int peer_pid_ = 0;
  std::string peer_owner_;

public:
  ~WinIpcServer() override { close(); }

  bool start(const std::string &path) override {
#ifdef _WIN32
    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    SECURITY_ATTRIBUTES security_attributes = {};
    security_attributes.nLength = sizeof(security_attributes);
    security_attributes.bInheritHandle = FALSE;

    // LocalSystem owns the service process, but the desktop client runs as the
    // interactive user. Grant interactive users pipe read/write access while
    // keeping full access for LocalSystem and Administrators.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)", SDDL_REVISION_1,
            &security_descriptor, NULL)) {
      exv::observability::LogFacade::error("Helper: failed to build named pipe security descriptor");
      return false;
    }
    security_attributes.lpSecurityDescriptor = security_descriptor;

    hPipe_ = CreateNamedPipeA(
        path.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &security_attributes);

    if (security_descriptor) {
      LocalFree(security_descriptor);
    }

    if (hPipe_ == INVALID_HANDLE_VALUE) {
      exv::observability::LogFacade::event(
          "ERROR", "helper", "helper.pipe.create_failed",
          "Helper failed to create named pipe",
          {{"endpoint", path},
           {"win32_error", std::to_string(GetLastError())}});
      return false;
    }

    return true;
#else
    (void)path;
    return false;
#endif
  }

  bool accept_client() override {
#ifdef _WIN32
    if (!ConnectNamedPipe(hPipe_, NULL)) {
      DWORD err = GetLastError();
      if (err != ERROR_PIPE_CONNECTED) {
        exv::observability::LogFacade::event(
            "WARN", "helper", "helper.pipe.accept_failed",
            "Helper failed while accepting named pipe client",
            {{"win32_error", std::to_string(err)}});
        return false;
      }
    }
    return true;
#else
    return false;
#endif
  }

  bool verify_client() override {
#ifdef _WIN32
    peer_owner_.clear();
    peer_uid_ = 0;
    peer_gid_ = 0;
    peer_pid_ = 0;

    ULONG client_pid = 0;
    if (GetNamedPipeClientProcessId(hPipe_, &client_pid)) {
      peer_pid_ = static_cast<int>(client_pid);
    }

    HANDLE process = nullptr;
    if (peer_pid_ > 0) {
      process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                            static_cast<DWORD>(peer_pid_));
    }
    if (process) {
      HANDLE token = nullptr;
      if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
        DWORD sid_size = 0;
        GetTokenInformation(token, TokenUser, NULL, 0, &sid_size);
        if (sid_size > 0) {
          std::vector<BYTE> sid_buf(sid_size);
          auto *token_user = reinterpret_cast<TOKEN_USER *>(sid_buf.data());
          if (GetTokenInformation(token, TokenUser, token_user, sid_size,
                                  &sid_size)) {
            LPSTR sid_string = nullptr;
            if (ConvertSidToStringSidA(token_user->User.Sid, &sid_string)) {
              peer_owner_ = sid_string;
              LocalFree(sid_string);
            }
          }
        }
        CloseHandle(token);
      }
      CloseHandle(process);
    }

    // Access is controlled by the named pipe DACL. The daemon-level owner
    // check decides whether a oneshot client is allowed.
    return true;
#else
    return false;
#endif
  }

  std::string read_request(int timeout_ms = -1) override {
#ifdef _WIN32
    std::string raw;
    char buffer[4096];
    DWORD bytesRead = 0;

    if (timeout_ms >= 0) {
      const DWORD start = GetTickCount();
      while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(hPipe_, NULL, 0, NULL, &available, NULL)) {
          exv::observability::LogFacade::event(
              "WARN", "helper", "helper.pipe.peek_failed",
              "Helper failed while waiting for initial request bytes",
              {{"win32_error", std::to_string(GetLastError())},
               {"timeout_ms", std::to_string(timeout_ms)}});
          return "";
        }
        if (available > 0) {
          break;
        }
        if (static_cast<int>(GetTickCount() - start) >= timeout_ms) {
          exv::observability::LogFacade::event(
              "WARN", "helper", "helper.pipe.initial_request_timeout",
              "Helper timed out waiting for initial request bytes",
              {{"timeout_ms", std::to_string(timeout_ms)}});
          return "";
        }
        Sleep(25);
      }
    }

    while (true) {
      BOOL success = ReadFile(hPipe_, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
      if (!success || bytesRead == 0) {
        const DWORD err = success ? ERROR_SUCCESS : GetLastError();
        const bool expected_disconnect =
            timeout_ms < 0 &&
            (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED ||
             err == ERROR_NO_DATA);
        if (!expected_disconnect) {
          exv::observability::LogFacade::event(
              "WARN", "helper", "helper.pipe.read_failed",
              "Helper failed while reading named pipe request",
              {{"win32_error", std::to_string(err)},
               {"bytes_read", std::to_string(bytesRead)}});
        }
        break;
      }
      raw.append(buffer, bytesRead);
      if (raw.find('\n') != std::string::npos)
        break;
    }
    return raw;
#else
    (void)timeout_ms;
    return "";
#endif
  }

  bool send_response(const std::string &response) override {
#ifdef _WIN32
    std::string payload = response;
    payload.push_back('\n');
    DWORD bytesWritten = 0;
    BOOL success = WriteFile(hPipe_, payload.c_str(),
                              static_cast<DWORD>(payload.size()), &bytesWritten, NULL);
    const DWORD write_error = success ? ERROR_SUCCESS : GetLastError();
    BOOL flushed = success ? FlushFileBuffers(hPipe_) : FALSE;
    const DWORD flush_error = flushed ? ERROR_SUCCESS : GetLastError();
    if (!success || bytesWritten != payload.size() || !flushed) {
      exv::observability::LogFacade::event(
          "ERROR", "helper", "helper.pipe.write_failed",
          "Helper failed while writing named pipe response",
          {{"write_ok", success ? "true" : "false"},
           {"flush_ok", flushed ? "true" : "false"},
           {"win32_error", std::to_string(success ? flush_error : write_error)},
           {"bytes_expected", std::to_string(payload.size())},
           {"bytes_written", std::to_string(bytesWritten)}});
    }
    return success && bytesWritten == payload.size() && flushed;
#else
    (void)response;
    return false;
#endif
  }

  void close() override {
#ifdef _WIN32
    if (hPipe_ != INVALID_HANDLE_VALUE) {
      CloseHandle(hPipe_);
      hPipe_ = INVALID_HANDLE_VALUE;
    }
#endif
  }

  void close_client() override {
#ifdef _WIN32
    if (hPipe_ != INVALID_HANDLE_VALUE) {
      DisconnectNamedPipe(hPipe_);
    }
#endif
  }

  unsigned int peer_uid() const override { return peer_uid_; }
  unsigned int peer_gid() const override { return peer_gid_; }
  std::string peer_owner() const override { return peer_owner_; }
  int peer_pid() const override { return peer_pid_; }
};

std::unique_ptr<IpcServer> create_ipc_server() {
  return std::make_unique<WinIpcServer>();
}

} // namespace helper
} // namespace exv
