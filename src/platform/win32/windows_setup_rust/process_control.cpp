#include "windows_setup_rust/process_control.hpp"

#include "windows_setup_rust/util/hidden_process.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstring>
#include <string>

namespace exv::setup {
namespace {

std::wstring ToLower(std::wstring v) {
  for (auto &ch : v) {
    if (ch >= L'A' && ch <= L'Z') {
      ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
  }
  return v;
}

}  // namespace

bool TryGracefulCoreShutdown(int connect_timeout_ms) {
  HANDLE pipe = CreateFileW(L"\\\\.\\pipe\\exv-core-ipc-v1",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            nullptr,
                            OPEN_EXISTING,
                            0,
                            nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    return false;
  }

  // Best-effort connect wait already done by CreateFile when pipe exists.
  (void)connect_timeout_ms;
  DWORD mode = PIPE_READMODE_BYTE;
  SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

  const char *msg = "{\"id\":990001,\"action\":\"core.shutdown\",\"payload\":{}}\n";
  DWORD written = 0;
  WriteFile(pipe, msg, static_cast<DWORD>(std::strlen(msg)), &written, nullptr);

  char response[512];
  DWORD read = 0;
  const bool got = ReadFile(pipe, response, sizeof(response), &read, nullptr) && read > 0;
  CloseHandle(pipe);
  return got;
}

int TerminateProcessesByImageName(const std::wstring &image_name) {
  const auto target = ToLower(image_name);
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0;
  }

  int attempts = 0;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      if (ToLower(pe.szExeFile) == target) {
        HANDLE proc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);        if (proc != nullptr) {
          if (TerminateProcess(proc, 1)) {
            ++attempts;
          }
          WaitForSingleObject(proc, 2000);
          CloseHandle(proc);
        }
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return attempts;
}

bool IsAnyExvProcessRunning() {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return false;
  }

  bool found = false;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      const std::wstring name = ToLower(pe.szExeFile);
      if (name == L"exv-ui.exe" || name == L"exv-core.exe" || name == L"exv-engine.exe") {
        found = true;
        break;
      }
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return found;
}

void StopRunningAppProcesses() {
  if (TryGracefulCoreShutdown(500)) {
    Sleep(1200);
  } else {
    Sleep(300);
  }
  TerminateProcessesByImageName(L"exv-ui.exe");
  TerminateProcessesByImageName(L"exv-core.exe");
  TerminateProcessesByImageName(L"exv-engine.exe");
  Sleep(300);
  // Hidden fallbacks matching NSIS taskkill behavior.
  TaskKillImage(L"exv-ui.exe");
  TaskKillImage(L"exv-core.exe");
  TaskKillImage(L"exv-engine.exe");
}

}  // namespace exv::setup
