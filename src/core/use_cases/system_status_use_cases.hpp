#pragma once

#include "core/config/config_manager.hpp"
#include "core/use_cases/use_case_result.hpp"
#include "helper/common/helper_messages.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace exv::core {

class SystemStatusUseCases {
public:
  SystemStatusUseCases();
  explicit SystemStatusUseCases(std::string config_dir);

  UseCaseResult service_status();
  UseCaseResult helper_status();
  UseCaseResult runtime_status();
  UseCaseResult driver_status();
  UseCaseResult install_driver(const nlohmann::json &payload);
  UseCaseResult cli_status();
  UseCaseResult install_cli();
  UseCaseResult uninstall_cli();
  UseCaseResult install_helper();
  UseCaseResult uninstall_helper();
  UseCaseResult repair_helper();

private:
  exv::config::ConfigManager manager_;
};

} // namespace exv::core
