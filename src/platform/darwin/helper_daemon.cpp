#include "helper/helper_ipc.hpp"

#include <cerrno>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace exv {
namespace helper {

class MacIpcServer : public IpcServer {
  int server_fd_ = -1;
  int client_fd_ = -1;
  unsigned int peer_uid_ = 0;
  unsigned int peer_gid_ = 0;
  int peer_pid_ = 0;

public:
  ~MacIpcServer() override { close(); }

  bool start(const std::string &path) override {
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0)
      return false;

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());

    // Remove any stale socket left by a previous daemon that exited without
    // cleaning up (SIGKILL, crash, or a prior bind() failure). On macOS an
    // AF_UNIX name can remain "in use" even after the file is gone, so bind()
    // would fail with EADDRINUSE and the daemon would never come up — leaving
    // the service stuck in installed-but-unavailable and crashing in a tight
    // launchd KeepAlive loop. unlink() clears both the file and the lingering
    // name binding; ignore ENOENT (nothing to remove).
    if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
      ::close(server_fd_);
      server_fd_ = -1;
      return false;
    }

    if (bind(server_fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
      ::close(server_fd_);
      server_fd_ = -1;
      return false;
    }

    // macOS: group staff (gid 20) — all local user accounts
    chmod(path.c_str(), 0660);
    chown(path.c_str(), 0, 20);

    if (listen(server_fd_, 8) != 0) {
      ::close(server_fd_);
      server_fd_ = -1;
      std::remove(path.c_str());
      return false;
    }
    return true;
  }

  bool accept_client() override {
    client_fd_ = ::accept(server_fd_, nullptr, nullptr);
    if (client_fd_ < 0)
      return false;

    int flags = fcntl(client_fd_, F_GETFD);
    if (flags >= 0)
      fcntl(client_fd_, F_SETFD, flags | FD_CLOEXEC);

    return true;
  }

  bool verify_client() override {
    uid_t uid = 0;
    gid_t gid = 0;
    if (getpeereid(client_fd_, &uid, &gid) != 0) {
      ::close(client_fd_);
      client_fd_ = -1;
      return false;
    }
    peer_uid_ = static_cast<unsigned int>(uid);
    peer_gid_ = static_cast<unsigned int>(gid);
    return true;
  }

  std::string read_request(int timeout_ms = -1) override {
    if (timeout_ms >= 0) {
      pollfd fd {};
      fd.fd = client_fd_;
      fd.events = POLLIN;
      const int ready = poll(&fd, 1, timeout_ms);
      if (ready <= 0 || (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) ||
          !(fd.revents & POLLIN)) {
        return "";
      }
    }

    std::string raw;
    char buffer[1024];
    ssize_t n = 0;
    // Read until newline (not EOF) to support persistent connections.
    while ((n = read(client_fd_, buffer, sizeof(buffer))) > 0) {
      raw.append(buffer, buffer + n);
      if (raw.find('\n') != std::string::npos)
        break;
    }
    return raw;
  }

  bool send_response(const std::string &response) override {
    std::string payload = response;
    payload.push_back('\n');
    // Loop on short writes: a single write() can return fewer bytes than
    // requested (kernel send-buffer pressure), which would truncate the
    // response frame on the wire. The client frames on '\n', so a truncated
    // frame yields a valid-looking envelope with missing fields (e.g. an empty
    // payload_json) that the client then fails to parse. Write until the whole
    // payload is flushed or the connection errors out.
    const char *data = payload.data();
    size_t remaining = payload.size();
    while (remaining > 0) {
      ssize_t written = ::write(client_fd_, data, remaining);
      if (written < 0) {
        if (errno == EINTR)
          continue;
        return false;
      }
      if (written == 0)
        return false;
      data += written;
      remaining -= static_cast<size_t>(written);
    }
    // Do NOT close client_fd_ here -- keep connection open for persistent IPC.
    // The caller is responsible for calling close_client() when done.
    return true;
  }

  void close_client() override {
    if (client_fd_ >= 0) {
      ::close(client_fd_);
      client_fd_ = -1;
    }
  }

  void close_server() override {
    if (server_fd_ >= 0) {
      ::close(server_fd_);
      server_fd_ = -1;
    }
  }

  void close() override {
    close_client();
    close_server();
  }

  int server_fd() const override { return server_fd_; }

  unsigned int peer_uid() const override { return peer_uid_; }
  unsigned int peer_gid() const override { return peer_gid_; }
  int peer_pid() const override { return peer_pid_; }
};

std::unique_ptr<IpcServer> create_ipc_server() {
  return std::make_unique<MacIpcServer>();
}

} // namespace helper
} // namespace exv
