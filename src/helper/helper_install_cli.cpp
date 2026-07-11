#include "helper/helper_install_cli.hpp"

#include "platform/common/helper_service_manager.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace exv::helper {

int run_install_cli(const std::string &subcommand,
                    const std::vector<std::string> & /*args*/) {
  if (subcommand == "install-service") {
    return exv::platform::install_helper_service(
        std::string{}, exv::platform::HelperServiceManagerContext{});
  }
  if (subcommand == "uninstall-service") {
    return exv::platform::uninstall_helper_service(
        exv::platform::HelperServiceManagerContext{});
  }
  if (subcommand == "repair-service") {
    return exv::platform::repair_helper_service(
        exv::platform::HelperServiceManagerContext{});
  }
  std::cerr << "Unknown subcommand: " << subcommand << std::endl;
  return 2;
}

} // namespace exv::helper
