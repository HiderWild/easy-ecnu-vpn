#include "helper/helper_single_instance.hpp"

#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>

namespace exv::helper {
namespace {

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

std::string lock_path(HelperInstanceKind kind) {
  return kind == HelperInstanceKind::Service
             ? "/var/run/exv-helper-service.lock"
             : "/var/run/exv-helper-oneshot.lock";
}

} // namespace

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
