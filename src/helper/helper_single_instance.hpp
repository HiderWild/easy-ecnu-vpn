#pragma once

#include <memory>

namespace exv::helper {

// Which kind of helper instance is asserting uniqueness. A service helper and
// a one-shot helper use independent locks: by design only one is ever needed
// at a time (the backend resolver never starts a one-shot while a service is
// installed).
enum class HelperInstanceKind { Oneshot, Service };

// Opaque handle returned by acquire_single_instance. Destroying it (or letting
// it go out of scope) releases the underlying lock. A null handle means
// another instance already holds the lock.
using SingleInstanceHandle =
    std::unique_ptr<void, void (*)(void *)>;

// Attempt to acquire the single-instance lock for the given kind. Returns a
// non-null handle on success (the caller is the unique instance). Returns a
// null handle if another instance of the same kind is already running; the
// caller must exit immediately.
SingleInstanceHandle acquire_single_instance(HelperInstanceKind kind);

} // namespace exv::helper
