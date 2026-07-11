#include "core/pipe_ipc.hpp"
#include "core/lifecycle/core_paths.hpp"
#include "observability/log_facade.hpp"
#include "platform/common/logging/log_runtime.hpp"
#include "runtime/runtime_context.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#endif

#include <chrono>
#include <thread>

namespace exv::core {

std::string core_pipe_path() {
  return exv::core::lifecycle::core_ipc_path();
}

#ifdef _WIN32
// ── Windows Named Pipe implementation ──────────────────────────

struct PipeIpcListener::Impl {
  HANDLE pipe_handle = INVALID_HANDLE_VALUE;
  std::string path;
};

PipeIpcListener::PipeIpcListener(const std::string& pipe_path)
    : impl_(std::make_unique<Impl>()) {
  impl_->path = pipe_path;
}

PipeIpcListener::~PipeIpcListener() { stop(); }

bool PipeIpcListener::start() {
  PSECURITY_DESCRIPTOR security_descriptor = nullptr;
  SECURITY_ATTRIBUTES security_attributes{};
  SECURITY_ATTRIBUTES *pipe_security = nullptr;
  if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
          "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)",
          SDDL_REVISION_1, &security_descriptor, nullptr)) {
    security_attributes.nLength = sizeof(security_attributes);
    security_attributes.lpSecurityDescriptor = security_descriptor;
    security_attributes.bInheritHandle = FALSE;
    pipe_security = &security_attributes;
  }

  impl_->pipe_handle = CreateNamedPipeA(
      impl_->path.c_str(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
      PIPE_UNLIMITED_INSTANCES, // Allow multiple simultaneous connections
      8192,     // out buffer size
      8192,     // in buffer size
      0,        // default timeout
      pipe_security);
  if (security_descriptor) {
    LocalFree(security_descriptor);
  }
  if (impl_->pipe_handle == INVALID_HANDLE_VALUE) {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::error(
        "Pipe IPC listener failed to bind Windows named pipe '" + impl_->path +
        "' GetLastError=" + std::to_string(error));
    return false;
  }
  return true;
}

void PipeIpcListener::stop() {
  if (impl_->pipe_handle != INVALID_HANDLE_VALUE) {
    DisconnectNamedPipe(impl_->pipe_handle);
    CloseHandle(impl_->pipe_handle);
    impl_->pipe_handle = INVALID_HANDLE_VALUE;
  }
}

bool PipeIpcListener::accept_one(PipeRequestHandler handler) {
  if (impl_->pipe_handle == INVALID_HANDLE_VALUE) return false;

  // Non-blocking check: see if a client is waiting
  if (!ConnectNamedPipe(impl_->pipe_handle, nullptr)) {
    DWORD err = GetLastError();
    if (err != ERROR_PIPE_CONNECTED) {
      return false; // no client waiting
    }
  }

  // Read one line. Windows nonblocking named pipes can report ERROR_NO_DATA
  // for a client that has connected but has not written its first bytes yet.
  // Give the client a short grace period; otherwise a normal connect/write
  // sequence can race with the server poll loop and get disconnected.
  char buffer[8192] = {};
  DWORD bytes_read = 0;
  const auto read_deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(impl_->pipe_handle, nullptr, 0, nullptr, &available,
                      nullptr) &&
        available > 0) {
      if (ReadFile(impl_->pipe_handle, buffer, sizeof(buffer) - 1,
                   &bytes_read, nullptr)) {
        break;
      }
      DisconnectNamedPipe(impl_->pipe_handle);
      return false;
    }

    const DWORD err = GetLastError();
    if (available == 0 || err == ERROR_NO_DATA || err == ERROR_PIPE_LISTENING) {
      if (std::chrono::steady_clock::now() < read_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        continue;
      }
    }
    DisconnectNamedPipe(impl_->pipe_handle);
    return false;
  }
  if (bytes_read == 0) {
    DisconnectNamedPipe(impl_->pipe_handle);
    return false;
  }
  std::string request(buffer, bytes_read);
  // Trim trailing whitespace
  while (!request.empty() &&
         (request.back() == '\n' || request.back() == '\r')) {
    request.pop_back();
  }

  // Dispatch
  std::string response = handler(request);
  response.push_back('\n');

  // Write response
  DWORD bytes_written = 0;
  WriteFile(impl_->pipe_handle, response.c_str(),
            static_cast<DWORD>(response.size()), &bytes_written, nullptr);
  FlushFileBuffers(impl_->pipe_handle);
  DisconnectNamedPipe(impl_->pipe_handle);
  return true;
}

void* PipeIpcListener::native_handle() const {
  return impl_->pipe_handle;
}

#else
// ── Unix socket implementation ─────────────────────────────────

struct PipeIpcListener::Impl {
  int listen_fd = -1;
  std::string path;
};

PipeIpcListener::PipeIpcListener(const std::string& pipe_path)
    : impl_(std::make_unique<Impl>()) {
  impl_->path = pipe_path;
}

PipeIpcListener::~PipeIpcListener() { stop(); }

bool PipeIpcListener::start() {
  impl_->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (impl_->listen_fd < 0) return false;

  // Remove stale socket file
  unlink(impl_->path.c_str());

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, impl_->path.c_str(), sizeof(addr.sun_path) - 1);

  if (bind(impl_->listen_fd, reinterpret_cast<sockaddr*>(&addr),
           sizeof(addr)) != 0) {
    close(impl_->listen_fd);
    impl_->listen_fd = -1;
    return false;
  }

  if (listen(impl_->listen_fd, 5) != 0) {
    close(impl_->listen_fd);
    impl_->listen_fd = -1;
    return false;
  }

  // Set non-blocking
  int flags = fcntl(impl_->listen_fd, F_GETFL, 0);
  fcntl(impl_->listen_fd, F_SETFL, flags | O_NONBLOCK);

  return true;
}

void PipeIpcListener::stop() {
  if (impl_->listen_fd >= 0) {
    close(impl_->listen_fd);
    impl_->listen_fd = -1;
  }
  unlink(impl_->path.c_str());
}

bool PipeIpcListener::accept_one(PipeRequestHandler handler) {
  if (impl_->listen_fd < 0) return false;

  int client_fd = accept(impl_->listen_fd, nullptr, nullptr);
  if (client_fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
    return false;
  }

  // Read one line
  char buffer[8192] = {};
  ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
  if (n <= 0) {
    close(client_fd);
    return false;
  }
  std::string request(buffer, static_cast<size_t>(n));
  while (!request.empty() &&
         (request.back() == '\n' || request.back() == '\r')) {
    request.pop_back();
  }

  // Dispatch
  std::string response = handler(request);
  response.push_back('\n');

  // Write response
  write(client_fd, response.c_str(), response.size());
  close(client_fd);
  return true;
}

void* PipeIpcListener::native_handle() const {
  return reinterpret_cast<void*>(static_cast<intptr_t>(impl_->listen_fd));
}
#endif

} // namespace exv::core
