#pragma once
#include <string>
#include <vector>

namespace exv::helper {

// Execute install/uninstall/repair subcommands (run as an elevated,
// short-lived process separate from the helper daemon). Returns process
// exit code: 0 success, 2 usage error, 1 install failure.
int run_install_cli(const std::string &subcommand,
                    const std::vector<std::string> &args);

} // namespace exv::helper
