#pragma once

#include <string>

namespace exv::setup {

bool CreateShortcut(const std::wstring &link_path,
                    const std::wstring &target_path,
                    const std::wstring &icon_path = {},
                    const std::wstring &working_dir = {});

bool CreateStartMenuShortcuts(const std::wstring &install_dir);
bool CreateDesktopShortcut(const std::wstring &install_dir);
bool CreateQuickLaunchShortcut(const std::wstring &install_dir);

bool RemoveDesktopShortcut();
bool RemoveStartMenuShortcuts();
bool RemoveQuickLaunchShortcut();

}  // namespace exv::setup
