#pragma once

#include <string>

namespace exv::setup {

// Try graceful core.shutdown over named pipe, then terminate remaining
// exv-ui.exe / exv-core.exe / exv-engine.exe processes. Always non-throwing;
// best-effort.
void StopRunningAppProcesses();

// 只探测不结束：是否有任一 EXV 进程（exv-ui/core/engine）正在运行。
// 安装前检查旧版本实例时使用，避免「无进程也要走一遍结束流程」。
bool IsAnyExvProcessRunning();

// Terminate all processes whose image name matches (case-insensitive).
// Returns number of terminate attempts.
int TerminateProcessesByImageName(const std::wstring &image_name);

// Send core.shutdown JSON line to \\.\pipe\exv-core-ipc-v1.
// Returns true if a response line was read.
bool TryGracefulCoreShutdown(int connect_timeout_ms = 500);

}  // namespace exv::setup
