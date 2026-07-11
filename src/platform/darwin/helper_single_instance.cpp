#include "helper/helper_single_instance.hpp"

#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

#include <mutex>
#include <string>
#include <utility>

namespace exv::helper {
namespace {

std::mutex g_test_namespace_mutex;
std::string g_test_namespace;

struct FlockHandle {
  int fd;
};

void release(void *p) {
  auto *f = static_cast<FlockHandle *>(p);
  if (f && f->fd >= 0) {
    flock(f->fd, LOCK_UN);
    close(f->fd);
  }
  delete f;
}

std::string sanitize_namespace(std::string name) {
  for (char &ch : name) {
    const bool alpha = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
    const bool digit = ch >= '0' && ch <= '9';
    if (!alpha && !digit && ch != '-' && ch != '_' && ch != '.') {
      ch = '-';
    }
  }
  return name;
}

std::string current_test_namespace() {
  std::lock_guard<std::mutex> lock(g_test_namespace_mutex);
  return g_test_namespace;
}

std::string lock_path(HelperInstanceKind kind) {
  const std::string test_namespace = current_test_namespace();
  if (!test_namespace.empty()) {
    switch (kind) {
    case HelperInstanceKind::Global:
      return "/tmp/exv-helper-" + test_namespace + "-daemon.lock";
    case HelperInstanceKind::Service:
      return "/tmp/exv-helper-" + test_namespace + "-service.lock";
    case HelperInstanceKind::Oneshot:
      return "/tmp/exv-helper-" + test_namespace + "-oneshot.lock";
    }
    return "/tmp/exv-helper-" + test_namespace + "-daemon.lock";
  }

  switch (kind) {
  case HelperInstanceKind::Global:
    return "/var/run/exv-helper-daemon.lock";
  case HelperInstanceKind::Service:
    return "/var/run/exv-helper-service.lock";
  case HelperInstanceKind::Oneshot:
    return "/var/run/exv-helper-oneshot.lock";
  }
  return "/var/run/exv-helper-daemon.lock";
}

} // namespace

SingleInstanceTestScope::SingleInstanceTestScope() = default;

SingleInstanceTestScope::SingleInstanceTestScope(std::string previous_namespace)
    : previous_namespace_(std::move(previous_namespace)), active_(true) {}

SingleInstanceTestScope::~SingleInstanceTestScope() {
  if (!active_) return;
  std::lock_guard<std::mutex> lock(g_test_namespace_mutex);
  g_test_namespace = std::move(previous_namespace_);
}

SingleInstanceTestScope::SingleInstanceTestScope(
    SingleInstanceTestScope &&other) noexcept
    : previous_namespace_(std::move(other.previous_namespace_)),
      active_(other.active_) {
  other.active_ = false;
}

SingleInstanceTestScope &SingleInstanceTestScope::operator=(
    SingleInstanceTestScope &&other) noexcept {
  if (this == &other) return *this;
  if (active_) {
    std::lock_guard<std::mutex> lock(g_test_namespace_mutex);
    g_test_namespace = std::move(previous_namespace_);
  }
  previous_namespace_ = std::move(other.previous_namespace_);
  active_ = other.active_;
  other.active_ = false;
  return *this;
}

SingleInstanceTestScope
override_single_instance_namespace_for_test(std::string name) {
  std::lock_guard<std::mutex> lock(g_test_namespace_mutex);
  SingleInstanceTestScope scope(g_test_namespace);
  g_test_namespace = sanitize_namespace(std::move(name));
  return scope;
}

SingleInstanceHandle acquire_single_instance(HelperInstanceKind kind) {
  int fd = open(lock_path(kind).c_str(), O_CREAT | O_RDWR, 0644);
  if (fd < 0) {
    return {nullptr, release};
  }
  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    close(fd);
    return {nullptr, release};
  }
  return {new FlockHandle{fd}, release};
}

} // namespace exv::helper
