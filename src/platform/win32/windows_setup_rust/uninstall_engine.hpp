#pragma once

#include "windows_setup_rust/progress_model.hpp"

#include <string>

namespace exv::setup {

struct UninstallRequest {
  std::wstring install_dir;  // empty → read registry
  bool clear_user_data{false};
};

struct UninstallResult {
  bool ok{false};
  std::wstring error;
};

UninstallResult RunUninstall(const UninstallRequest &request, ProgressModel *progress = nullptr);

}  // namespace exv::setup
