#pragma once

namespace exv::helper {

// Why the helper daemon is exiting. The exit cleanup path is conditioned on
// this reason: only a timeout-class exit (the peer has gone away and left
// privileged resources behind) triggers the safety-net cleanup of managed
// sessions. A normal caller-driven exit leaves sessions intact for the caller
// (e.g. core reconnect) to take over.
enum class HelperExitReason {
  // Shutdown op / service stop / request_daemon_stop: the caller is actively
  // taking over or winding down. Sessions are left intact; no cleanup.
  Normal,
  // Heartbeat / core-lease timeout, or oneshot parent process disappeared: the
  // peer is gone and privileged resources are orphaned. Force cleanup.
  Timeout,
  // Forced kill / crash: the daemon does not pass through an orderly exit, so
  // this reason is informational only. Orphaned resources are mopped up by the
  // single-instance assertion and uninstall cleanup, not by the exit path.
  External,
};

inline bool should_cleanup_on_exit(HelperExitReason reason) {
  return reason == HelperExitReason::Timeout;
}

} // namespace exv::helper
