#include "helper/helper_single_instance.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

namespace exv::helper {
namespace {

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

std::string mutex_name(HelperInstanceKind kind) {
  return kind == HelperInstanceKind::Service ? "Global\\exv-helper-service"
                                             : "Global\\exv-helper-oneshot";
}

} // namespace

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
