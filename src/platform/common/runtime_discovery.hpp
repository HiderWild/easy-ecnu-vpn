#pragma once

#include <string>
#include <vector>

namespace exv::platform {

std::string get_bundled_runtime_dir();
std::string get_bundled_wintun_path();
std::vector<std::string> stable_service_payload_file_names();
std::vector<std::string> stable_service_runtime_asset_names();
std::vector<std::string> stable_service_runtime_candidates_for_source(
    const std::string &source_executable, const std::string &asset_name);
std::vector<std::string>
stable_service_wintun_candidates_for_source(const std::string &source_executable);
std::string stable_service_executable_from_binary_path(
    const std::string &binary_path);
bool stable_service_binary_path_targets_executable(
    const std::string &binary_path, const std::string &expected_executable);
std::string get_bundled_tap_installer_path();

} // namespace exv::platform

