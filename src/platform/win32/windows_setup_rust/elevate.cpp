#include "windows_setup_rust/elevate.hpp"

#include "windows_setup_rust/service_control.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <cstdint>

namespace exv::setup {
namespace {

std::wstring GetSelfPath() {
  wchar_t path[MAX_PATH] = {};
  const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
  if (n == 0 || n >= MAX_PATH) {
    return {};
  }
  return path;
}

bool WriteAll(HANDLE pipe, const std::string &s) {
  DWORD written = 0;
  return WriteFile(pipe, s.data(), static_cast<DWORD>(s.size()), &written, nullptr) &&
         written == s.size();
}

bool ReadLine(HANDLE pipe, std::string &line, int timeout_ms) {
  line.clear();
  const DWORD start = GetTickCount();
  char ch = 0;
  DWORD read = 0;
  while (true) {
    if (timeout_ms >= 0 && GetTickCount() - start > static_cast<DWORD>(timeout_ms)) {
      return false;
    }
    if (!ReadFile(pipe, &ch, 1, &read, nullptr) || read == 0) {
      return !line.empty();
    }
    if (ch == '\n') {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      return true;
    }
    line.push_back(ch);
    if (line.size() > 4096) {
      return false;
    }
  }
}

}  // namespace

bool IsProcessElevated() {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return false;
  }
  TOKEN_ELEVATION elev{};
  DWORD size = 0;
  const BOOL ok =
      GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size);
  CloseHandle(token);
  return ok && elev.TokenIsElevated != 0;
}

bool CanWriteDirectory(const std::wstring &directory) {
  std::error_code ec;
  std::filesystem::create_directories(directory, ec);
  if (ec) {
    return false;
  }
  const auto probe = std::filesystem::path(directory) / L".exv_write_probe";
  HANDLE file = CreateFileW(probe.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    return false;
  }
  CloseHandle(file);
  return true;
}

std::wstring GenerateElevationToken() {
  std::uint8_t bytes[16] = {};
  // Prefer RtlGenRandom via SystemFunction036 if available; fallback to tick+pid.
  HMODULE adv = GetModuleHandleW(L"advapi32.dll");
  using RtlGenRandomFn = BOOLEAN(APIENTRY *)(PVOID, ULONG);
  auto fn = adv ? reinterpret_cast<RtlGenRandomFn>(GetProcAddress(adv, "SystemFunction036"))
                : nullptr;
  if (fn == nullptr || !fn(bytes, sizeof(bytes))) {
    const auto t = GetTickCount64();
    const auto p = GetCurrentProcessId();
    std::memcpy(bytes, &t, sizeof(t) > 8 ? 8 : sizeof(t));
    std::memcpy(bytes + 8, &p, sizeof(p));
  }
  wchar_t hex[33] = {};
  for (int i = 0; i < 16; ++i) {
    std::swprintf(hex + i * 2, 3, L"%02x", bytes[i]);
  }
  return hex;
}

std::wstring DefaultElevationPipeName() {
  return L"\\\\.\\pipe\\exv-setup-elev-" + std::to_wstring(GetCurrentProcessId());
}

bool RunElevatedWorker(const std::wstring &pipe_name, const std::wstring &token) {
  const auto self = GetSelfPath();
  if (self.empty()) {
    return false;
  }

  // Create pipe server first so worker can connect.
  HANDLE pipe = CreateNamedPipeW(pipe_name.c_str(),
                                 PIPE_ACCESS_DUPLEX,
                                 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                 1,
                                 4096,
                                 4096,
                                 20000,
                                 nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    return false;
  }

  const std::wstring params = L"/elevated-worker --pipe \"" + pipe_name + L"\" --token \"" +
                              token + L"\"";

  SHELLEXECUTEINFOW sei{};
  sei.cbSize = sizeof(sei);
  sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  sei.lpVerb = L"runas";
  sei.lpFile = self.c_str();
  sei.lpParameters = params.c_str();
  sei.nShow = SW_HIDE;

  if (!ShellExecuteExW(&sei)) {
    CloseHandle(pipe);
    return false;
  }

  // Wait for worker to connect.
  if (!ConnectNamedPipe(pipe, nullptr)) {
    if (GetLastError() != ERROR_PIPE_CONNECTED) {
      if (sei.hProcess) {
        TerminateProcess(sei.hProcess, 1);
        CloseHandle(sei.hProcess);
      }
      CloseHandle(pipe);
      return false;
    }
  }

  // Authenticate.
  if (!WriteAll(pipe, "HELLO " + std::string(token.begin(), token.end()) + "\n")) {
    CloseHandle(pipe);
    if (sei.hProcess) {
      CloseHandle(sei.hProcess);
    }
    return false;
  }
  std::string reply;
  if (!ReadLine(pipe, reply, 15000) || reply.rfind("OK", 0) != 0) {
    CloseHandle(pipe);
    if (sei.hProcess) {
      CloseHandle(sei.hProcess);
    }
    return false;
  }

  auto call = [&](const char *op) -> bool {
    if (!WriteAll(pipe, std::string("OP ") + op + "\n")) {
      return false;
    }
    std::string r;
    if (!ReadLine(pipe, r, 60000)) {
      return false;
    }
    return r.rfind("OK", 0) == 0;
  };

  const bool ok = call("stop_service");
  call("quit");

  CloseHandle(pipe);
  if (sei.hProcess) {
    WaitForSingleObject(sei.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return ok && code == 0;
  }
  return ok;
}

bool EnsureServiceStopped() {
  const auto presence = QueryServicePresence(kEngineServiceName);
  if (presence == ServicePresence::NotInstalled) {
    return true;
  }
  if (presence == ServicePresence::Error) {
    return false;
  }
  if (IsProcessElevated()) {
    return StopService(kEngineServiceName);
  }
  return RunElevatedWorker(DefaultElevationPipeName(), GenerateElevationToken());
}

int RunElevatedWorkerServer(const std::wstring &pipe_name, const std::wstring &token) {
  // Worker is launched elevated; connect as client to parent's pipe.
  HANDLE pipe = INVALID_HANDLE_VALUE;
  for (int i = 0; i < 100; ++i) {
    pipe = CreateFileW(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                       OPEN_EXISTING, 0, nullptr);
    if (pipe != INVALID_HANDLE_VALUE) {
      break;
    }
    Sleep(50);
  }
  if (pipe == INVALID_HANDLE_VALUE) {
    return 1;
  }

  std::string line;
  if (!ReadLine(pipe, line, 10000)) {
    CloseHandle(pipe);
    return 1;
  }
  const std::string expected = "HELLO " + std::string(token.begin(), token.end());
  if (line != expected) {
    WriteAll(pipe, "ERR bad token\n");
    CloseHandle(pipe);
    return 1;
  }
  WriteAll(pipe, "OK\n");

  while (ReadLine(pipe, line, 120000)) {
    if (line.rfind("OP ", 0) != 0) {
      WriteAll(pipe, "ERR bad op\n");
      continue;
    }
    const auto op = line.substr(3);
    if (op == "quit") {
      WriteAll(pipe, "OK\n");
      break;
    }
    if (op == "stop_service") {
      const bool ok = StopService(kEngineServiceName);
      WriteAll(pipe, ok ? "OK\n" : "ERR service\n");
      continue;
    }
    WriteAll(pipe, "ERR unknown\n");
  }
  CloseHandle(pipe);
  return 0;
}

}  // namespace exv::setup
