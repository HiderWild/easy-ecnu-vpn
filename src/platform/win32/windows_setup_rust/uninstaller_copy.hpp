#pragma once

#include <cstdint>
#include <string>

namespace exv::setup {

struct UninstallerWriteResult {
  bool ok{false};
  std::uint32_t win32_error{0};
  std::wstring error;
};

// Safely replace install_dir\Uninstall.exe with source_path. The old target remains in place until
// its replacement has been fully staged in the same directory.
UninstallerWriteResult WriteUninstallerCopy(const std::wstring &source_path,
                                            const std::wstring &install_dir);

}  // namespace exv::setup
