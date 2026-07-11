#pragma once

#include <memory>
#include <string>

namespace exv::helper {

// Which helper instance scope is asserting uniqueness. Helper daemons first
// acquire the global lock so service and one-shot daemons cannot run at the
// same time, then acquire their mode-specific lock to preserve per-mode
// single-instance semantics.
enum class HelperInstanceKind { Global, Oneshot, Service };

// Opaque handle returned by acquire_single_instance. Destroying it (or letting
// it go out of scope) releases the underlying lock. A null handle means
// another instance already holds the lock.
using SingleInstanceHandle =
    std::unique_ptr<void, void (*)(void *)>;

// Attempt to acquire the single-instance lock for the given kind. Returns a
// non-null handle on success (the caller is the unique instance). Returns a
// null handle if another instance of that scope is already running; the caller
// must exit immediately.
SingleInstanceHandle acquire_single_instance(HelperInstanceKind kind);

class SingleInstanceTestScope {
public:
  SingleInstanceTestScope();
  ~SingleInstanceTestScope();

  SingleInstanceTestScope(const SingleInstanceTestScope &) = delete;
  SingleInstanceTestScope &
  operator=(const SingleInstanceTestScope &) = delete;

  SingleInstanceTestScope(SingleInstanceTestScope &&other) noexcept;
  SingleInstanceTestScope &
  operator=(SingleInstanceTestScope &&other) noexcept;

private:
  friend SingleInstanceTestScope
  override_single_instance_namespace_for_test(std::string name);

  explicit SingleInstanceTestScope(std::string previous_namespace);

  std::string previous_namespace_;
  bool active_ = false;
};

// Test-only override for isolating process-global helper locks from real helper
// services. Destroying the returned scope restores the prior namespace.
SingleInstanceTestScope
override_single_instance_namespace_for_test(std::string name);

} // namespace exv::helper
