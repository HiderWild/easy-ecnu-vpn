#include "windows_setup_rust/util/hidden_process.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <vector>

namespace exv::setup {

HiddenProcessResult RunHidden(const std::wstring &application,
                              const std::wstring &command_line,
                              int timeout_ms) {
  HiddenProcessResult result;

  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;

  HANDLE read_pipe = nullptr;
  HANDLE write_pipe = nullptr;
  if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
    return result;
  }
  SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdOutput = write_pipe;
  si.hStdError = write_pipe;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION pi{};
  std::wstring mutable_cmd = command_line;
  const wchar_t *app = application.empty() ? nullptr : application.c_str();

  const BOOL ok = CreateProcessW(app,
                                 mutable_cmd.empty() ? nullptr : mutable_cmd.data(),
                                 nullptr,
                                 nullptr,
                                 TRUE,
                                 CREATE_NO_WINDOW,
                                 nullptr,
                                 nullptr,
                                 &si,
                                 &pi);
  CloseHandle(write_pipe);
  write_pipe = nullptr;

  if (!ok) {
    CloseHandle(read_pipe);
    return result;
  }
  result.started = true;

  std::string output;
  char buffer[512];
  DWORD read = 0;
  while (ReadFile(read_pipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
    output.append(buffer, buffer + read);
  }
  CloseHandle(read_pipe);

  const DWORD wait_ms = timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms);
  WaitForSingleObject(pi.hProcess, wait_ms);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  result.exit_code = code;
  result.captured_stdout = std::move(output);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  return result;
}

bool TaskKillImage(const std::wstring &image_name) {
  const std::wstring cmd =
      L"taskkill.exe /IM " + image_name + L" /T /F";
  const auto r = RunHidden(L"", cmd, 15000);
  return r.started && (r.exit_code == 0 || r.exit_code == 128);  // 128 = not found
}

}  // namespace exv::setup
