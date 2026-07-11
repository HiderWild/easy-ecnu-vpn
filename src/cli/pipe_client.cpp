#include "cli/pipe_client.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <cstring>
#include <iostream>
#include <thread>
#include <chrono>

namespace exv::cli {

PipeClient::~PipeClient() { disconnect(); }

bool PipeClient::connect(const std::string& pipe_path) {
  if (connected_) return true;

#ifdef _WIN32
  // Retry up to 5 times with 50ms delay if pipe is busy
  for (int attempt = 0; attempt < 5; ++attempt) {
    HANDLE hPipe = CreateFileA(
        pipe_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hPipe != INVALID_HANDLE_VALUE) {
      handle_ = hPipe;
      connected_ = true;
      return true;
    }

    DWORD err = GetLastError();
    if (err == ERROR_PIPE_BUSY && attempt < 4) {
      // Pipe is busy, wait and retry
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      continue;
    }

    // Only fail on non-retryable errors
    if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PIPE_BUSY) {
      return false;
    }
  }
  return false;
#else
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return false;
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, pipe_path.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return false;
  }
  handle_ = reinterpret_cast<void*>(static_cast<intptr_t>(fd));
#endif

  connected_ = true;
  return true;
}

std::string PipeClient::send_request(const std::string& request_line) {
  if (!connected_) return {};

  std::string wire = request_line;
  if (wire.empty() || wire.back() != '\n') wire.push_back('\n');

#ifdef _WIN32
  HANDLE hPipe = static_cast<HANDLE>(handle_);
  DWORD written = 0;
  if (!WriteFile(hPipe, wire.c_str(), static_cast<DWORD>(wire.size()), &written, nullptr)) {
    disconnect();
    return {};
  }
  char buf[8192] = {};
  DWORD bytes_read = 0;
  if (!ReadFile(hPipe, buf, sizeof(buf) - 1, &bytes_read, nullptr) || bytes_read == 0) {
    disconnect();
    return {};
  }
  std::string response(buf, bytes_read);
#else
  int fd = static_cast<int>(reinterpret_cast<intptr_t>(handle_));
  if (::write(fd, wire.c_str(), wire.size()) <= 0) {
    disconnect();
    return {};
  }
  char buf[8192] = {};
  ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
  if (n <= 0) {
    disconnect();
    return {};
  }
  std::string response(buf, static_cast<size_t>(n));
#endif

  while (!response.empty() && (response.back() == '\n' || response.back() == '\r'))
    response.pop_back();
  return response;
}

void PipeClient::disconnect() {
  if (!connected_) return;
  connected_ = false;
#ifdef _WIN32
  if (handle_) { CloseHandle(static_cast<HANDLE>(handle_)); handle_ = nullptr; }
#else
  int fd = static_cast<int>(reinterpret_cast<intptr_t>(handle_));
  if (fd >= 0) { ::close(fd); handle_ = nullptr; }
#endif
}

bool PipeClient::is_connected() const { return connected_; }

bool PipeClient::probe(const std::string& pipe_path) {
  PipeClient client;
  bool ok = client.connect(pipe_path);
  if (ok) {
    client.disconnect();
  }
  return ok;
}

} // namespace exv::cli
