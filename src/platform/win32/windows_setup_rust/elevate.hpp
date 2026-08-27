#pragma once

#include <string>

namespace exv::setup {

// True if current process token is elevated.
bool IsProcessElevated();

// True if directory can be created/written by current user.
bool CanWriteDirectory(const std::wstring &directory);

// Launch self with /elevated-worker via ShellExecuteExW runas + SW_HIDE.
// Blocks until worker exits. Returns true if elevated process exited 0.
bool RunElevatedWorker(const std::wstring &pipe_name, const std::wstring &token);

// Stop an installed engine service while preserving its SCM registration.
// Uses the current token when elevated and otherwise a hidden runas worker.
bool EnsureServiceStopped();

// Generate a simple one-time token (hex of random bytes).
std::wstring GenerateElevationToken();

// Default pipe name for this parent pid.
std::wstring DefaultElevationPipeName();

// Run elevated worker server side (called from ElevatedWorker role).
// Speaks a line protocol on the named pipe:
//   HELLO <token>
//   OP stop_service
//   OP quit
// Replies: OK / ERR <msg>
int RunElevatedWorkerServer(const std::wstring &pipe_name, const std::wstring &token);

}  // namespace exv::setup
