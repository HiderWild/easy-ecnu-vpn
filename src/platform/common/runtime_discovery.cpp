#include "platform/common/runtime_discovery.hpp"

#include "platform/common/file_system.hpp"
#include "platform/common/path_utils.hpp"
#include "platform/common/process_utils.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace exv::platform {
namespace {

constexpr const char *kWintunRuntimeAsset = "wintun.dll";

std::string trim_copy(const std::string &value) {
  const auto first = std::find_if_not(value.begin(), value.end(),
                                      [](unsigned char ch) {
                                        return std::isspace(ch) != 0;
                                      });
  if (first == value.end()) {
    return "";
  }
  const auto last = std::find_if_not(value.rbegin(), value.rend(),
                                     [](unsigned char ch) {
                                       return std::isspace(ch) != 0;
                                     })
                        .base();
  return std::string(first, last);
}

std::string ascii_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return value;
}

std::string normalize_windows_like_path(std::string path) {
  path = trim_copy(path);
  std::replace(path.begin(), path.end(), '/', '\\');
  if (path.rfind("\\\\?\\", 0) == 0) {
    path.erase(0, 4);
  } else if (path.rfind("\\??\\", 0) == 0) {
    path.erase(0, 4);
  }

  std::filesystem::path normalized(path);
  path = normalized.lexically_normal().string();
  std::replace(path.begin(), path.end(), '/', '\\');
  while (path.size() > 3 && path.back() == '\\') {
    path.pop_back();
  }
  return ascii_lower(path);
}

std::vector<std::string> candidate_runtime_dirs() {
  std::vector<std::string> dirs;

  const char *env_runtime_dir = std::getenv("EXV_RUNTIME_DIR");
  if (env_runtime_dir && *env_runtime_dir) {
    dirs.push_back(env_runtime_dir);
  }

  std::string exec_path = get_executable_path();
  if (!exec_path.empty()) {
    std::filesystem::path exec_dir =
        std::filesystem::path(exec_path).parent_path();
    dirs.push_back(exec_dir.string());
    dirs.push_back(join_path(exec_dir.string(), "runtime"));
  }

  return dirs;
}

std::string first_existing_file(const std::vector<std::string> &paths) {
  for (const auto &path : paths) {
    if (!path.empty() && file_exists(path)) {
      return path;
    }
  }
  return "";
}

} // namespace

std::string get_bundled_runtime_dir() {
  for (const auto &dir : candidate_runtime_dirs()) {
    if (!dir.empty() && file_exists(dir)) {
      return dir;
    }
  }
  return "";
}

std::string get_bundled_wintun_path() {
#ifdef _WIN32
  std::vector<std::string> candidates;
  for (const auto &dir : candidate_runtime_dirs()) {
    if (!dir.empty()) {
      candidates.push_back(join_path(dir, kWintunRuntimeAsset));
    }
  }
  return first_existing_file(candidates);
#else
  return "";
#endif
}

std::vector<std::string> stable_service_payload_file_names() {
  return {"exv-helper.exe", "wintun.dll", "libgcc_s_seh-1.dll",
          "libstdc++-6.dll", "libwinpthread-1.dll"};
}

std::vector<std::string> stable_service_runtime_asset_names() {
  return {"wintun.dll", "libgcc_s_seh-1.dll", "libstdc++-6.dll",
          "libwinpthread-1.dll"};
}

std::vector<std::string> stable_service_runtime_candidates_for_source(
    const std::string &source_executable, const std::string &asset_name) {
  std::vector<std::string> candidates;

  const std::filesystem::path source_dir =
      std::filesystem::path(source_executable).parent_path();
  if (!source_dir.empty()) {
    candidates.push_back((source_dir / asset_name).string());
    candidates.push_back((source_dir / "runtime" / asset_name).string());
  }

  const std::filesystem::path package_root = source_dir.parent_path();
  if (!package_root.empty() && package_root != source_dir) {
    candidates.push_back((package_root / asset_name).string());
    candidates.push_back((package_root / "runtime" / asset_name).string());
  }

  return candidates;
}

std::vector<std::string> stable_service_wintun_candidates_for_source(
    const std::string &source_executable) {
  return stable_service_runtime_candidates_for_source(source_executable,
                                                      kWintunRuntimeAsset);
}

std::string stable_service_executable_from_binary_path(
    const std::string &binary_path) {
  const std::string trimmed = trim_copy(binary_path);
  if (trimmed.empty()) {
    return "";
  }

  if (trimmed.front() == '"') {
    const size_t closing_quote = trimmed.find('"', 1);
    if (closing_quote != std::string::npos) {
      return trimmed.substr(1, closing_quote - 1);
    }
    return trimmed.substr(1);
  }

  const std::string lower = ascii_lower(trimmed);
  const size_t exe_suffix = lower.find(".exe");
  if (exe_suffix != std::string::npos) {
    return trim_copy(trimmed.substr(0, exe_suffix + 4));
  }

  const size_t first_space = trimmed.find_first_of(" \t\r\n");
  return first_space == std::string::npos ? trimmed
                                          : trimmed.substr(0, first_space);
}

bool stable_service_binary_path_targets_executable(
    const std::string &binary_path, const std::string &expected_executable) {
  const std::string parsed =
      stable_service_executable_from_binary_path(binary_path);
  if (parsed.empty() || expected_executable.empty()) {
    return false;
  }
  return normalize_windows_like_path(parsed) ==
         normalize_windows_like_path(expected_executable);
}

std::string get_bundled_tap_installer_path() {
#ifdef _WIN32
  std::vector<std::string> candidates;
  for (const auto &dir : candidate_runtime_dirs()) {
    if (dir.empty()) {
      continue;
    }
    candidates.push_back(join_path(dir, "tap-windows-installer.exe"));
    candidates.push_back(join_path(dir, "tap-windows-amd64.exe"));
    candidates.push_back(join_path(dir, "tap-windows-x86.exe"));
    candidates.push_back(join_path(dir, "tap-windows/OemVista.inf"));
    candidates.push_back(join_path(dir, "tap/OemVista.inf"));
  }
  return first_existing_file(candidates);
#else
  return "";
#endif
}

} // namespace exv::platform

