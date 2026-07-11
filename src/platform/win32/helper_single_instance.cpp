#include "helper/helper_single_instance.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <mutex>
#include <string>
#include <utility>

namespace exv::helper {
namespace {

std::mutex g_test_namespace_mutex;
std::string g_test_namespace;

struct MutexHandle {
  HANDLE h;
};

void release(void *p) {
  auto *m = static_cast<MutexHandle *>(p);
  if (m && m->h) {
    ReleaseMutex(m->h);
    CloseHandle(m->h);
  }
  delete m;
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

std::string mutex_name(HelperInstanceKind kind) {
  const std::string test_namespace = current_test_namespace();
  if (!test_namespace.empty()) {
    switch (kind) {
    case HelperInstanceKind::Global:
      return "Global\\exv-helper-" + test_namespace + "-daemon";
    case HelperInstanceKind::Service:
      return "Global\\exv-helper-" + test_namespace + "-service";
    case HelperInstanceKind::Oneshot:
      return "Global\\exv-helper-" + test_namespace + "-oneshot";
    }
    return "Global\\exv-helper-" + test_namespace + "-daemon";
  }

  switch (kind) {
  case HelperInstanceKind::Global:
    return "Global\\exv-helper-daemon";
  case HelperInstanceKind::Service:
    return "Global\\exv-helper-service";
  case HelperInstanceKind::Oneshot:
    return "Global\\exv-helper-oneshot";
  }
  return "Global\\exv-helper-daemon";
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
  HANDLE h = CreateMutexA(nullptr, TRUE, mutex_name(kind).c_str());
  if (h == nullptr) {
    return {nullptr, release};
  }
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(h);
    return {nullptr, release};
  }
  return {new MutexHandle{h}, release};
}

} // namespace exv::helper
