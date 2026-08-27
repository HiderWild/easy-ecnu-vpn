#include "windows_setup_rust/cli.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Expect(bool condition, const char *message) {
  if (!condition) {
    std::cerr << "EXPECT FAILED: " << message << '\n';
    ++failures;
  }
}

std::vector<std::wstring> MakeArgs(std::initializer_list<const wchar_t *> parts) {
  std::vector<std::wstring> storage;
  storage.reserve(parts.size());
  for (const auto *part : parts) {
    storage.emplace_back(part);
  }
  return storage;
}

std::vector<wchar_t *> Pointers(std::vector<std::wstring> &storage) {
  std::vector<wchar_t *> pointers;
  pointers.reserve(storage.size());
  for (auto &value : storage) {
    pointers.push_back(value.data());
  }
  return pointers;
}

}  // namespace

int main() {
  {
    auto storage = MakeArgs({L"exv-setup.exe"});
    auto pointers = Pointers(storage);
    const auto options = exv::setup::ParseCli(static_cast<int>(pointers.size()), pointers.data());
    Expect(options.has_value(), "default install parse succeeds");
    if (options) {
      Expect(exv::setup::ResolveGuiInstallDir(false, *options) == exv::setup::DefaultInstallDir(),
             "install GUI keeps default directory behavior");
    }
  }

  {
    auto storage = MakeArgs({L"Uninstall.exe", L"/uninstall"});
    auto pointers = Pointers(storage);
    const auto options = exv::setup::ParseCli(static_cast<int>(pointers.size()), pointers.data());
    Expect(options.has_value(), "uninstall GUI parse succeeds");
    if (options) {
      Expect(exv::setup::ResolveGuiInstallDir(true, *options).empty(),
             "uninstall GUI without /D preserves empty directory for registry lookup");
    }
  }

  {
    auto storage = MakeArgs({L"Uninstall.exe", L"/uninstall", L"/D=C:\\Custom\\EXV"});
    auto pointers = Pointers(storage);
    const auto options = exv::setup::ParseCli(static_cast<int>(pointers.size()), pointers.data());
    Expect(options.has_value(), "explicit uninstall directory parse succeeds");
    if (options) {
      Expect(exv::setup::ResolveGuiInstallDir(true, *options) == L"C:\\Custom\\EXV",
             "uninstall GUI preserves explicit /D directory");
    }
  }

  if (failures != 0) {
    return 1;
  }
  std::cout << "p1_setup_regression_test: ok\n";
  return 0;
}
