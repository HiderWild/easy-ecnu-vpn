#pragma once

#include "windows_setup_rust/cli.hpp"
#include "windows_setup_rust/progress_model.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace exv::setup::ui {

// Direct2D installer window:
//  Home (card) -> Progress (transparent wave) -> Finish (card)
// or Uninstall confirm -> reverse wave progress.
int RunInstallerGui(const CliOptions &options);
int RunUninstallerGui(const CliOptions &options);

}  // namespace exv::setup::ui
