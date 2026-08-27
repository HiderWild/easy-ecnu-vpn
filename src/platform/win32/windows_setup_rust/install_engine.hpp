#pragma once

#include "windows_setup_rust/cli.hpp"
#include "windows_setup_rust/progress_model.hpp"

#include <string>
#include <vector>

namespace exv::setup {

struct InstallRequest {
  std::wstring install_dir;
  std::wstring app_version{L"0.0.0"};
  bool create_desktop_shortcut{true};
  bool create_start_menu{true};
  bool create_quick_launch{false};
  bool launch_app{false};  // finish page may launch after success
  // When empty, extract embedded payload resource. When set, treat as EXVP file or package dir.
  std::wstring payload_path;
  // If true, payload_path is a directory to copy (dev/test), not EXVP.
  bool payload_is_directory{false};
};

struct InstallResult {
  bool ok{false};
  std::wstring error;
  std::wstring install_dir;
};

InstallResult RunInstall(const InstallRequest &request, ProgressModel *progress = nullptr);

// Copy self to install_dir\Uninstall.exe
bool WriteUninstallerCopy(const std::wstring &install_dir);

// Launch $INSTDIR\exv-ui.exe (validates PE). Used by finish page.
bool LaunchExvUi(const std::wstring &install_dir, std::wstring *error = nullptr);

}  // namespace exv::setup
