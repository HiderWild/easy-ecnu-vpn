#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace exv::setup {

struct HiddenProcessResult {
  bool started{false};
  std::uint32_t exit_code{0xFFFFFFFFu};
  std::string captured_stdout;
};

// CreateProcessW with CREATE_NO_WINDOW. Waits until exit if timeout_ms >= 0.
// timeout_ms < 0 means wait forever.
HiddenProcessResult RunHidden(const std::wstring &application,
                              const std::wstring &command_line,
                              int timeout_ms = 60000);

// Convenience: run taskkill.exe /IM <image> /T /F hidden.
bool TaskKillImage(const std::wstring &image_name);

}  // namespace exv::setup
