#include "platform/common/file_system.hpp"
#include "platform/common/interface_stats.hpp"
#include "platform/common/process_utils.hpp"
#include "platform/common/runtime_discovery.hpp"
#include "platform/common/runtime_paths.hpp"
#include "platform/common/helper_service_manager.hpp"

#include "observability/log_facade.hpp"
#include "platform/common/helper_platform.hpp"
#include "platform/common/service_status.hpp"
#include "platform/win32/windows_strings.hpp"
#include "cli/console.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <tlhelp32.h>

namespace exv {
namespace platform {
namespace {

constexpr const wchar_t *kStableHelperDirectorySddl =
    L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
constexpr const wchar_t *kStableHelperPayloadSddl =
    L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)";

struct ScopedHandle {
  HANDLE value = INVALID_HANDLE_VALUE;

  ScopedHandle() = default;
  explicit ScopedHandle(HANDLE handle) : value(handle) {}
  ScopedHandle(const ScopedHandle &) = delete;
  ScopedHandle &operator=(const ScopedHandle &) = delete;
  ScopedHandle(ScopedHandle &&other) noexcept : value(other.value) {
    other.value = INVALID_HANDLE_VALUE;
  }
  ScopedHandle &operator=(ScopedHandle &&other) noexcept {
    if (this != &other) {
      reset(other.value);
      other.value = INVALID_HANDLE_VALUE;
    }
    return *this;
  }
  ~ScopedHandle() { reset(); }

  explicit operator bool() const { return value != INVALID_HANDLE_VALUE; }

  void reset(HANDLE handle = INVALID_HANDLE_VALUE) {
    if (value != INVALID_HANDLE_VALUE) {
      CloseHandle(value);
    }
    value = handle;
  }
};

struct StableHelperAcePolicy {
  WELL_KNOWN_SID_TYPE sid_type;
  DWORD access_mask;
  BYTE ace_flags;
};

struct StableHelperPayloadEntry {
  std::string name;
  std::filesystem::path source;
  std::filesystem::path target;
  bool runtime = false;
};

constexpr std::array<StableHelperAcePolicy, 3> kStableHelperDirectoryAces{{
    {WinLocalSystemSid, FILE_ALL_ACCESS,
     OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS,
     OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE},
    {WinBuiltinUsersSid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
     OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE},
}};

constexpr std::array<StableHelperAcePolicy, 3> kStableHelperPayloadAces{{
    {WinLocalSystemSid, FILE_ALL_ACCESS, 0},
    {WinBuiltinAdministratorsSid, FILE_ALL_ACCESS, 0},
    {WinBuiltinUsersSid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, 0},
}};

bool wait_until_ready(const HelperServiceManagerContext &context, int attempts,
                     unsigned int delay_us) {
  return context.wait_until_available &&
         context.wait_until_available(attempts, delay_us);
}

bool send_helper_request(const HelperServiceManagerContext &context,
                         const nlohmann::json &request,
                         nlohmann::json *response,
                         std::string *error_message,
                         int timeout_seconds = 15) {
  return context.send_request &&
         context.send_request(request, response, error_message,
                              timeout_seconds);
}

void print_runtime_status_if_available(const HelperServiceManagerContext &context,
                                       bool available) {
  (void)context;
  if (!available)
    return;
}

void report_stable_helper_directory_error(const std::string &message) {
  cli::print_error(message);
  exv::observability::LogFacade::error(message);
}

std::string win32_message(DWORD error) {
  return windows_error_message(error);
}

bool enable_stable_helper_security_privilege(const char *privilege_name) {
  ScopedHandle token;
  HANDLE raw_token = INVALID_HANDLE_VALUE;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw_token)) {
    return false;
  }
  token.reset(raw_token);

  TOKEN_PRIVILEGES privileges = {};
  privileges.PrivilegeCount = 1;
  if (!LookupPrivilegeValueA(nullptr, privilege_name,
                             &privileges.Privileges[0].Luid)) {
    return false;
  }
  privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(token.value, FALSE, &privileges, 0, nullptr,
                             nullptr)) {
    return false;
  }
  return GetLastError() == ERROR_SUCCESS;
}

void enable_stable_helper_security_privileges() {
  static const bool attempted = [] {
    enable_stable_helper_security_privilege(SE_TAKE_OWNERSHIP_NAME);
    enable_stable_helper_security_privilege(SE_RESTORE_NAME);
    return true;
  }();
  (void)attempted;
}

bool inspect_stable_helper_path(const std::filesystem::path &path,
                                bool expect_directory, bool *exists) {
  if (exists) {
    *exists = false;
  }

  const std::wstring native_path = path.wstring();
  const DWORD attributes = GetFileAttributesW(native_path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return true;
    }
    report_stable_helper_directory_error(
        "Failed to inspect stable helper path '" + path.string() +
        "': " + windows_error_message(error));
    return false;
  }

  if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    report_stable_helper_directory_error(
        "Refusing to use stable helper path because it is a reparse "
        "point: " +
        path.string());
    return false;
  }
  const bool is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  if (expect_directory != is_directory) {
    report_stable_helper_directory_error(
        std::string("Refusing to use stable helper path because it is ") +
        (expect_directory ? "not a directory: " : "a directory: ") +
        path.string());
    return false;
  }

  if (exists) {
    *exists = true;
  }
  return true;
}

bool is_trusted_stable_helper_owner(PSID owner) {
  return owner != nullptr &&
         (IsWellKnownSid(owner, WinBuiltinAdministratorsSid) ||
          IsWellKnownSid(owner, WinLocalSystemSid));
}

PSECURITY_DESCRIPTOR
build_stable_helper_security_descriptor(const wchar_t *security_sddl) {
  PSECURITY_DESCRIPTOR security_descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          security_sddl, SDDL_REVISION_1, &security_descriptor, nullptr)) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to build stable helper security descriptor: " +
        windows_error_message(error));
    return nullptr;
  }
  return security_descriptor;
}

bool ace_matches_stable_helper_policy(ACCESS_ALLOWED_ACE *ace,
                                      const StableHelperAcePolicy &policy) {
  if (!ace || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
    return false;
  }

  const BYTE inheritance_flags =
      ace->Header.AceFlags &
      (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE |
       NO_PROPAGATE_INHERIT_ACE | INHERITED_ACE);
  if (inheritance_flags != policy.ace_flags) {
    return false;
  }

  if (ace->Mask != policy.access_mask) {
    return false;
  }

  return IsWellKnownSid(reinterpret_cast<PSID>(&ace->SidStart),
                        policy.sid_type);
}

bool dacl_matches_stable_helper_policy(
    PACL dacl, const std::array<StableHelperAcePolicy, 3> &expected_aces) {
  if (!dacl) {
    return false;
  }

  ACL_SIZE_INFORMATION acl_info = {};
  if (!GetAclInformation(dacl, &acl_info, sizeof(acl_info),
                         AclSizeInformation)) {
    return false;
  }
  if (acl_info.AceCount != expected_aces.size()) {
    return false;
  }

  std::array<bool, 3> matched{};
  for (DWORD index = 0; index < acl_info.AceCount; ++index) {
    void *ace_ptr = nullptr;
    if (!GetAce(dacl, index, &ace_ptr) || !ace_ptr) {
      return false;
    }

    auto *ace = reinterpret_cast<ACCESS_ALLOWED_ACE *>(ace_ptr);
    bool found = false;
    for (size_t expected_index = 0; expected_index < expected_aces.size();
         ++expected_index) {
      if (matched[expected_index]) {
        continue;
      }
      if (ace_matches_stable_helper_policy(ace, expected_aces[expected_index])) {
        matched[expected_index] = true;
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }

  return std::all_of(matched.begin(), matched.end(),
                     [](bool value) { return value; });
}

bool verify_stable_helper_security(
    HANDLE handle, const std::filesystem::path &path,
    const std::array<StableHelperAcePolicy, 3> &expected_aces) {
  PSID owner = nullptr;
  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR security_descriptor = nullptr;
  const DWORD result = GetSecurityInfo(
      handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr,
      &dacl, nullptr, &security_descriptor);
  if (result != ERROR_SUCCESS) {
    report_stable_helper_directory_error(
        "Failed to verify stable helper security for '" + path.string() +
        "': " + windows_error_message(result));
    return false;
  }

  bool verified = true;
  SECURITY_DESCRIPTOR_CONTROL control = {};
  DWORD revision = 0;
  if (!is_trusted_stable_helper_owner(owner)) {
    report_stable_helper_directory_error(
        "Refusing to use stable helper path because its owner is not trusted: " +
        path.string());
    verified = false;
  } else if (!GetSecurityDescriptorControl(security_descriptor, &control,
                                           &revision)) {
    report_stable_helper_directory_error(
        "Failed to verify stable helper DACL control for '" + path.string() +
        "': " + windows_error_message(GetLastError()));
    verified = false;
  } else if ((control & SE_DACL_PROTECTED) == 0) {
    report_stable_helper_directory_error(
        "Refusing to use stable helper path because its DACL is not protected: " +
        path.string());
    verified = false;
  } else if (!dacl_matches_stable_helper_policy(dacl, expected_aces)) {
    report_stable_helper_directory_error(
        "Refusing to use stable helper path because its DACL does not match "
        "the expected service payload policy: " +
        path.string());
    verified = false;
  }

  LocalFree(security_descriptor);
  return verified;
}

ScopedHandle open_stable_helper_path_for_security(
    const std::filesystem::path &path, bool expect_directory) {
  const std::wstring native_path = path.wstring();
  const DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT |
                      (expect_directory ? FILE_FLAG_BACKUP_SEMANTICS : 0);
  ScopedHandle handle(CreateFileW(
      native_path.c_str(), READ_CONTROL | WRITE_DAC | WRITE_OWNER,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, flags, nullptr));
  if (!handle) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to open stable helper path for security hardening '" +
        path.string() + "': " + windows_error_message(error));
    return {};
  }

  BY_HANDLE_FILE_INFORMATION info = {};
  if (!GetFileInformationByHandle(handle.value, &info)) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to inspect stable helper handle '" + path.string() +
        "': " + windows_error_message(error));
    return {};
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    report_stable_helper_directory_error(
        "Refusing to harden stable helper path because it is a reparse point: " +
        path.string());
    return {};
  }
  const bool is_directory =
      (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  if (expect_directory != is_directory) {
    report_stable_helper_directory_error(
        std::string("Refusing to harden stable helper path because it is ") +
        (expect_directory ? "not a directory: " : "a directory: ") +
        path.string());
    return {};
  }

  return handle;
}

bool apply_stable_helper_security_to_handle(
    HANDLE handle, const std::filesystem::path &path,
    const wchar_t *security_sddl,
    const std::array<StableHelperAcePolicy, 3> &expected_aces) {
  enable_stable_helper_security_privileges();

  PSECURITY_DESCRIPTOR security_descriptor =
      build_stable_helper_security_descriptor(security_sddl);
  if (!security_descriptor) {
    return false;
  }

  PSID owner = nullptr;
  BOOL owner_defaulted = FALSE;
  if (!GetSecurityDescriptorOwner(security_descriptor, &owner,
                                  &owner_defaulted) ||
      owner == nullptr) {
    const DWORD error = GetLastError();
    LocalFree(security_descriptor);
    report_stable_helper_directory_error(
        "Failed to read stable helper owner from security descriptor: " +
        windows_error_message(error));
    return false;
  }

  PACL dacl = nullptr;
  BOOL dacl_present = FALSE;
  BOOL dacl_defaulted = FALSE;
  if (!GetSecurityDescriptorDacl(security_descriptor, &dacl_present, &dacl,
                                 &dacl_defaulted) ||
      !dacl_present || dacl == nullptr) {
    const DWORD error = GetLastError();
    LocalFree(security_descriptor);
    report_stable_helper_directory_error(
        "Failed to read stable helper ACL from security descriptor: " +
        windows_error_message(error));
    return false;
  }

  const DWORD result = SetSecurityInfo(
      handle, SE_FILE_OBJECT,
      OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
          PROTECTED_DACL_SECURITY_INFORMATION,
      owner, nullptr, dacl, nullptr);
  if (result != ERROR_SUCCESS) {
    LocalFree(security_descriptor);
    report_stable_helper_directory_error(
        "Failed to secure stable helper path '" + path.string() +
        "': " + windows_error_message(result));
    return false;
  }

  const bool security_verified =
      verify_stable_helper_security(handle, path, expected_aces);
  LocalFree(security_descriptor);
  return security_verified;
}

bool verify_existing_stable_helper_directory(
    const std::filesystem::path &directory) {
  bool exists = false;
  if (!inspect_stable_helper_path(directory, true, &exists) || !exists) {
    return false;
  }

  ScopedHandle handle = open_stable_helper_path_for_security(directory, true);
  if (!handle) {
    return false;
  }
  return verify_stable_helper_security(handle.value, directory,
                                       kStableHelperDirectoryAces);
}

bool create_stable_helper_directory_with_security(
    const std::filesystem::path &directory) {
  enable_stable_helper_security_privileges();

  PSECURITY_DESCRIPTOR security_descriptor =
      build_stable_helper_security_descriptor(kStableHelperDirectorySddl);
  if (!security_descriptor) {
    return false;
  }

  SECURITY_ATTRIBUTES security_attributes = {};
  security_attributes.nLength = sizeof(security_attributes);
  security_attributes.lpSecurityDescriptor = security_descriptor;
  security_attributes.bInheritHandle = FALSE;

  const std::wstring directory_path = directory.wstring();
  if (!CreateDirectoryW(directory_path.c_str(), &security_attributes)) {
    const DWORD error = GetLastError();
    LocalFree(security_descriptor);
    if (error == ERROR_ALREADY_EXISTS) {
      report_stable_helper_directory_error(
          "Refusing to trust pre-existing stable helper directory during "
          "secure create: " +
          directory.string());
    } else {
      report_stable_helper_directory_error(
          "Failed to create stable helper directory '" + directory.string() +
          "' with protected security: " + windows_error_message(error));
    }
    return false;
  }
  LocalFree(security_descriptor);

  bool exists = false;
  if (!inspect_stable_helper_path(directory, true, &exists) || !exists) {
    return false;
  }
  return verify_existing_stable_helper_directory(directory);
}

std::filesystem::path stable_helper_quarantine_path(
    const std::filesystem::path &directory, unsigned int attempt) {
  const std::string suffix = ".quarantine." +
                             std::to_string(GetCurrentProcessId()) + "." +
                             std::to_string(GetTickCount64()) + "." +
                             std::to_string(attempt);
  return directory.parent_path() / (directory.filename().string() + suffix);
}

std::string stable_helper_path_key(const std::filesystem::path &path) {
  std::string name = path.filename().string();
  std::transform(name.begin(), name.end(), name.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return name;
}

std::string stable_payload_name_key(const std::filesystem::path &path) {
  return stable_helper_path_key(path);
}

std::set<std::string> stable_payload_allowlist_keys() {
  std::set<std::string> allowlist;
  for (const auto &name : platform::stable_service_payload_file_names()) {
    allowlist.insert(stable_payload_name_key(name));
  }
  return allowlist;
}

bool stable_helper_tree_contains_reparse_point(
    const std::filesystem::path &path) {
  const DWORD root_attributes = GetFileAttributesW(path.wstring().c_str());
  if (root_attributes == INVALID_FILE_ATTRIBUTES) {
    return false;
  }
  if (root_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    return true;
  }
  if ((root_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
    return false;
  }

  std::error_code ec;
  for (std::filesystem::recursive_directory_iterator it(path, ec), end;
       it != end; it.increment(ec)) {
    if (ec) {
      return true;
    }
    const DWORD attributes = GetFileAttributesW(it->path().wstring().c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
      return true;
    }
  }
  return false;
}

std::filesystem::path choose_stable_helper_quarantine_path(
    const std::filesystem::path &directory) {
  for (unsigned int attempt = 0; attempt < 64; ++attempt) {
    const std::filesystem::path candidate =
        stable_helper_quarantine_path(directory, attempt);
    const DWORD attributes = GetFileAttributesW(candidate.wstring().c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
      continue;
    }
    const DWORD error = GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
      return candidate;
    }
    report_stable_helper_directory_error(
        "Failed to inspect stable helper quarantine destination '" +
        candidate.string() + "': " + windows_error_message(error));
    return {};
  }
  report_stable_helper_directory_error(
      "Unable to choose a unique stable helper quarantine path for: " +
      directory.string());
  return {};
}

bool stable_helper_directory_contains_only_manifest_payload(
    const std::filesystem::path &stable_helper_directory,
    const std::set<std::string> &allowlist) {
  bool exists = false;
  if (!inspect_stable_helper_path(stable_helper_directory, true, &exists)) {
    return false;
  }
  if (!exists) {
    return true;
  }

  std::error_code ec;
  for (std::filesystem::directory_iterator it(stable_helper_directory, ec), end;
       it != end; it.increment(ec)) {
    if (ec) {
      report_stable_helper_directory_error(
          "Failed to enumerate stable helper directory before quarantine '" +
          stable_helper_directory.string() + "': " + ec.message());
      return false;
    }

    const std::filesystem::path entry_path = it->path();
    const DWORD attributes = GetFileAttributesW(entry_path.wstring().c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD error = GetLastError();
      report_stable_helper_directory_error(
          "Failed to inspect stable helper payload before quarantine '" +
          entry_path.string() + "': " + windows_error_message(error));
      return false;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      report_stable_helper_directory_error(
          "Refusing to replace stable helper root because Helper contains a "
          "reparse point: " +
          entry_path.string());
      return false;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
      report_stable_helper_directory_error(
          "Refusing to replace stable helper root because Helper contains a directory: " +
          entry_path.string());
      return false;
    }
    if (allowlist.find(stable_payload_name_key(entry_path)) ==
        allowlist.end()) {
      report_stable_helper_directory_error(
          "Refusing to replace stable helper root because Helper contains non-manifest payload: " +
          entry_path.string());
      return false;
    }
  }
  if (ec) {
    report_stable_helper_directory_error(
        "Failed to enumerate stable helper directory before quarantine '" +
        stable_helper_directory.string() + "': " + ec.message());
    return false;
  }
  return true;
}

bool stable_helper_root_contains_only_manifest_payload(
    const std::filesystem::path &service_root,
    const std::filesystem::path &stable_helper_directory,
    const std::set<std::string> &allowlist) {
  const std::string helper_key = stable_helper_path_key(stable_helper_directory);
  std::error_code ec;
  for (std::filesystem::directory_iterator it(service_root, ec), end;
       it != end; it.increment(ec)) {
    if (ec) {
      report_stable_helper_directory_error(
          "Failed to enumerate stable helper root before quarantine '" +
          service_root.string() + "': " + ec.message());
      return false;
    }

    const std::filesystem::path entry_path = it->path();
    const DWORD attributes = GetFileAttributesW(entry_path.wstring().c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD error = GetLastError();
      report_stable_helper_directory_error(
          "Failed to inspect stable helper root entry before quarantine '" +
          entry_path.string() + "': " + windows_error_message(error));
      return false;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      report_stable_helper_directory_error(
          "Refusing to replace stable helper root because it contains a "
          "reparse point: " +
          entry_path.string());
      return false;
    }
    if (stable_helper_path_key(entry_path) != helper_key ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
      report_stable_helper_directory_error(
          "Refusing to replace stable helper root because it contains non-helper content: " +
          entry_path.string());
      return false;
    }
    if (!stable_helper_directory_contains_only_manifest_payload(entry_path,
                                                                allowlist)) {
      return false;
    }
  }
  if (ec) {
    report_stable_helper_directory_error(
        "Failed to enumerate stable helper root before quarantine '" +
        service_root.string() + "': " + ec.message());
    return false;
  }
  return true;
}

bool replace_untrusted_stable_helper_directory(
    const std::filesystem::path &directory,
    const std::filesystem::path &stable_helper_directory,
    const std::set<std::string> &allowlist) {
  bool exists = false;
  if (!inspect_stable_helper_path(directory, true, &exists)) {
    return false;
  }
  if (!exists) {
    return create_stable_helper_directory_with_security(directory);
  }

  if (!stable_helper_root_contains_only_manifest_payload(
          directory, stable_helper_directory, allowlist)) {
    return false;
  }
  const std::filesystem::path quarantine =
      choose_stable_helper_quarantine_path(directory);
  if (quarantine.empty()) {
    return false;
  }
  if (!MoveFileExW(directory.wstring().c_str(), quarantine.wstring().c_str(),
                   MOVEFILE_WRITE_THROUGH)) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Refusing to use untrusted stable helper directory because it could "
        "not be moved to quarantine '" +
        quarantine.string() + "': " + windows_error_message(error));
    return false;
  }

  if (!create_stable_helper_directory_with_security(directory)) {
    report_stable_helper_directory_error(
        "Failed to recreate stable helper directory after isolating the "
        "previous directory at quarantine path: " +
        quarantine.string());
    return false;
  }
  const std::string message =
      "Previous stable helper directory isolated; leaving quarantined copy for manual cleanup: " +
      quarantine.string();
  cli::print_info(message);
  exv::observability::LogFacade::info(message);
  return true;
}

bool recreate_stable_helper_directory_chain(
    const std::filesystem::path &stable_helper_directory) {
  if (stable_helper_directory.empty()) {
    report_stable_helper_directory_error(
        "Stable helper directory path is empty.");
    return false;
  }

  const std::filesystem::path service_root =
      stable_helper_directory.parent_path();
  if (service_root.empty() || service_root == stable_helper_directory) {
    report_stable_helper_directory_error(
        "Stable helper service root path is empty.");
    return false;
  }

  bool root_exists = false;
  if (!inspect_stable_helper_path(service_root, true, &root_exists)) {
    return false;
  }
  if (root_exists) {
    const auto allowlist = stable_payload_allowlist_keys();
    if (!stable_helper_root_contains_only_manifest_payload(
            service_root, stable_helper_directory, allowlist)) {
      return false;
    }
    if (stable_helper_tree_contains_reparse_point(service_root)) {
      report_stable_helper_directory_error(
          "Refusing to replace stable helper root because it contains a "
          "reparse point in the helper payload tree: " +
          service_root.string());
      return false;
    }
    if (!replace_untrusted_stable_helper_directory(
            service_root, stable_helper_directory, allowlist)) {
      return false;
    }
  } else if (!create_stable_helper_directory_with_security(service_root)) {
    return false;
  }

  return create_stable_helper_directory_with_security(stable_helper_directory);
}

bool ensure_secure_stable_helper_directory(
    const std::filesystem::path &stable_helper_directory) {
  return recreate_stable_helper_directory_chain(stable_helper_directory);
}

std::filesystem::path first_regular_file(
    const std::vector<std::filesystem::path> &candidates) {
  std::error_code ec;
  for (const auto &candidate : candidates) {
    if (!candidate.empty() && std::filesystem::is_regular_file(candidate, ec)) {
      return candidate;
    }
    ec.clear();
  }
  return {};
}

std::filesystem::path find_packaged_stable_runtime_asset(
    const std::filesystem::path &source_executable,
    const std::string &asset_name) {
  std::vector<std::filesystem::path> candidates;
  for (const auto &candidate :
       platform::stable_service_runtime_candidates_for_source(
           source_executable.string(), asset_name)) {
    if (!candidate.empty()) {
      candidates.emplace_back(candidate);
    }
  }

  return first_regular_file(candidates);
}

std::filesystem::path stable_helper_temp_payload_path(
    const std::filesystem::path &target) {
  const std::string temp_name = target.filename().string() + ".tmp." +
                                std::to_string(GetCurrentProcessId()) + "." +
                                std::to_string(GetTickCount64());
  return target.parent_path() / temp_name;
}

std::wstring normalize_stable_helper_final_path(std::wstring path) {
  constexpr const wchar_t *kDosPrefix = L"\\\\?\\";
  constexpr const wchar_t *kNtPrefix = L"\\??\\";
  constexpr const wchar_t *kUncPrefix = L"\\\\?\\UNC\\";
  if (path.rfind(kUncPrefix, 0) == 0) {
    path = L"\\\\" + path.substr(std::wcslen(kUncPrefix));
  } else if (path.rfind(kDosPrefix, 0) == 0) {
    path = path.substr(std::wcslen(kDosPrefix));
  } else if (path.rfind(kNtPrefix, 0) == 0) {
    path = path.substr(std::wcslen(kNtPrefix));
  }
  std::replace(path.begin(), path.end(), L'/', L'\\');
  return path;
}

std::wstring absolute_stable_helper_path_for_compare(
    const std::filesystem::path &path) {
  const std::wstring native_path = path.wstring();
  const DWORD required =
      GetFullPathNameW(native_path.c_str(), 0, nullptr, nullptr);
  if (required == 0) {
    return normalize_stable_helper_final_path(native_path);
  }
  std::vector<wchar_t> buffer(required + 1);
  const DWORD written = GetFullPathNameW(native_path.c_str(),
                                         static_cast<DWORD>(buffer.size()),
                                         buffer.data(), nullptr);
  if (written == 0 || written >= buffer.size()) {
    return normalize_stable_helper_final_path(native_path);
  }
  return normalize_stable_helper_final_path(
      std::wstring(buffer.data(), written));
}

bool same_stable_helper_path(const std::wstring &left,
                             const std::wstring &right) {
  return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) ==
         CSTR_EQUAL;
}

ScopedHandle open_stable_helper_payload_for_final_verification(
    const std::filesystem::path &target) {
  ScopedHandle handle(CreateFileW(
      target.wstring().c_str(), GENERIC_READ | READ_CONTROL | WRITE_DAC |
                                   WRITE_OWNER,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
      OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (!handle) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to open final stable helper payload for verification '" +
        target.string() + "': " + windows_error_message(error));
    return {};
  }

  BY_HANDLE_FILE_INFORMATION info = {};
  if (!GetFileInformationByHandle(handle.value, &info)) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to inspect final stable helper payload handle '" +
        target.string() + "': " + windows_error_message(error));
    return {};
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
    report_stable_helper_directory_error(
        "Refusing to use final stable helper payload because it is a reparse "
        "point: " +
        target.string());
    return {};
  }
  if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    report_stable_helper_directory_error(
        "Refusing to use final stable helper payload because it is a "
        "directory: " +
        target.string());
    return {};
  }
  return handle;
}

bool final_stable_helper_handle_targets_path(
    HANDLE handle, const std::filesystem::path &target,
    const std::string &asset_name) {
  std::vector<wchar_t> buffer(MAX_PATH);
  DWORD written = GetFinalPathNameByHandleW(
      handle, buffer.data(), static_cast<DWORD>(buffer.size()),
      FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (written >= buffer.size()) {
    buffer.assign(written + 1, L'\0');
    written = GetFinalPathNameByHandleW(
        handle, buffer.data(), static_cast<DWORD>(buffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  }
  if (written == 0 || written >= buffer.size()) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to resolve final stable helper payload path for " +
        asset_name + ": " + windows_error_message(error));
    return false;
  }

  const std::wstring actual =
      normalize_stable_helper_final_path(std::wstring(buffer.data(), written));
  const std::wstring expected = absolute_stable_helper_path_for_compare(target);
  if (!same_stable_helper_path(actual, expected)) {
    report_stable_helper_directory_error(
        "Final stable helper payload path mismatch for " + asset_name +
        ": expected " + target.string());
    return false;
  }
  return true;
}

bool file_contents_match_handle(const std::filesystem::path &source,
                                HANDLE target_handle) {
  std::error_code ec;
  const auto source_size = std::filesystem::file_size(source, ec);
  if (ec) {
    return false;
  }

  LARGE_INTEGER target_size = {};
  if (!GetFileSizeEx(target_handle, &target_size) ||
      target_size.QuadPart < 0 ||
      static_cast<std::uintmax_t>(target_size.QuadPart) != source_size) {
    return false;
  }

  std::ifstream source_stream(source, std::ios::binary);
  if (!source_stream) {
    return false;
  }

  LARGE_INTEGER zero = {};
  if (!SetFilePointerEx(target_handle, zero, nullptr, FILE_BEGIN)) {
    return false;
  }

  std::array<char, 65536> source_buffer{};
  std::array<char, 65536> target_buffer{};
  while (source_stream) {
    source_stream.read(source_buffer.data(), source_buffer.size());
    const std::streamsize source_read = source_stream.gcount();
    if (source_read <= 0) {
      break;
    }

    DWORD target_read = 0;
    if (!ReadFile(target_handle, target_buffer.data(),
                  static_cast<DWORD>(source_read), &target_read, nullptr) ||
        target_read != static_cast<DWORD>(source_read)) {
      return false;
    }
    if (!std::equal(source_buffer.begin(),
                    source_buffer.begin() + source_read,
                    target_buffer.begin())) {
      return false;
    }
  }

  SetFilePointerEx(target_handle, zero, nullptr, FILE_BEGIN);
  return source_stream.eof();
}

bool verify_final_stable_helper_payload(
    const std::filesystem::path &source, const std::filesystem::path &target,
    const std::string &asset_name) {
  ScopedHandle final_handle =
      open_stable_helper_payload_for_final_verification(target);
  if (!final_handle) {
    return false;
  }
  if (!final_stable_helper_handle_targets_path(final_handle.value, target,
                                               asset_name)) {
    return false;
  }
  if (!apply_stable_helper_security_to_handle(final_handle.value, target,
                                              kStableHelperPayloadSddl,
                                              kStableHelperPayloadAces)) {
    return false;
  }
  if (!file_contents_match_handle(source, final_handle.value)) {
    report_stable_helper_directory_error(
        "Stable helper payload content mismatch for " + asset_name + ": " +
        target.string());
    return false;
  }
  return verify_stable_helper_security(final_handle.value, target,
                                       kStableHelperPayloadAces);
}

bool remove_existing_stable_helper_temp_payload(
    const std::filesystem::path &temp_path) {
  bool temp_exists = false;
  if (!inspect_stable_helper_path(temp_path, false, &temp_exists)) {
    return false;
  }
  if (!temp_exists) {
    return true;
  }

  std::error_code ec;
  std::filesystem::remove(temp_path, ec);
  if (ec) {
    report_stable_helper_directory_error(
        "Failed to remove stale stable helper temp payload '" +
        temp_path.string() + "': " + ec.message());
    return false;
  }
  return true;
}

bool copy_payload_to_secure_temp(const std::filesystem::path &source,
                                 const std::filesystem::path &temp_path,
                                 const std::string &asset_name) {
  if (!remove_existing_stable_helper_temp_payload(temp_path)) {
    return false;
  }

  if (!CopyFileW(source.wstring().c_str(), temp_path.wstring().c_str(), TRUE)) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to copy stable helper payload " + asset_name +
        " to temp file '" + temp_path.string() +
        "': " + windows_error_message(error));
    return false;
  }

  return verify_final_stable_helper_payload(source, temp_path, asset_name);
}

bool replace_stable_helper_payload_from_temp(
    const std::filesystem::path &temp_path,
    const std::filesystem::path &target,
    const std::filesystem::path &source,
    const std::string &asset_name) {
  if (!MoveFileExW(temp_path.wstring().c_str(), target.wstring().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    const DWORD error = GetLastError();
    report_stable_helper_directory_error(
        "Failed to replace stable helper payload " + asset_name +
        " from temp file '" + temp_path.string() +
        "': " + windows_error_message(error));
    return false;
  }

  return verify_final_stable_helper_payload(source, target, asset_name);
}

bool validate_stable_helper_directory_manifest(
    const std::filesystem::path &stable_helper_directory,
    const std::set<std::string> &allowlist) {
  std::error_code ec;
  for (std::filesystem::directory_iterator it(stable_helper_directory, ec), end;
       it != end; it.increment(ec)) {
    if (ec) {
      report_stable_helper_directory_error(
          "Failed to enumerate stable helper directory '" +
          stable_helper_directory.string() + "': " + ec.message());
      return false;
    }

    const std::filesystem::path entry_path = it->path();
    const std::wstring native_path = entry_path.wstring();
    const DWORD attributes = GetFileAttributesW(native_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
      const DWORD error = GetLastError();
      report_stable_helper_directory_error(
          "Failed to inspect stable helper payload entry '" +
          entry_path.string() + "': " + windows_error_message(error));
      return false;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      report_stable_helper_directory_error(
          "Refusing to use stable helper payload directory because it contains "
          "a reparse point: " +
          entry_path.string());
      return false;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
      report_stable_helper_directory_error(
          "Refusing to use stable helper payload directory because it contains "
          "an unexpected directory: " +
          entry_path.string());
      return false;
    }
    if (allowlist.find(stable_payload_name_key(entry_path)) ==
        allowlist.end()) {
      report_stable_helper_directory_error(
          "Refusing to use stable helper payload directory because it contains "
          "an unexpected file: " +
          entry_path.string());
      return false;
    }
  }

  if (ec) {
    report_stable_helper_directory_error(
        "Failed to enumerate stable helper directory '" +
        stable_helper_directory.string() + "': " + ec.message());
    return false;
  }
  return true;
}

bool ensure_stable_helper_payload_asset(const std::filesystem::path &source,
                                        const std::filesystem::path &target,
                                        const std::string &asset_name,
                                        bool *refreshed) {
  if (refreshed)
    *refreshed = false;

  std::error_code ec;
  if (!std::filesystem::is_regular_file(source, ec)) {
    const std::string message =
        "Required stable helper payload file was not found in the package: " +
        asset_name + " (expected source: " + source.string() + ")";
    cli::print_error(message);
    exv::observability::LogFacade::error(message);
    return false;
  }

  bool target_exists = false;
  if (!inspect_stable_helper_path(target, false, &target_exists)) {
    return false;
  }

  ec.clear();
  if (target_exists) {
    ScopedHandle target_handle =
        open_stable_helper_payload_for_final_verification(target);
    if (!target_handle) {
      return false;
    }
    if (file_contents_match_handle(source, target_handle.value)) {
      return verify_final_stable_helper_payload(source, target, asset_name);
    }
  }

  const std::filesystem::path temp_path =
      stable_helper_temp_payload_path(target);
  if (!copy_payload_to_secure_temp(source, temp_path, asset_name)) {
    std::filesystem::remove(temp_path, ec);
    return false;
  }
  if (!replace_stable_helper_payload_from_temp(temp_path, target, source,
                                               asset_name)) {
    std::filesystem::remove(temp_path, ec);
    return false;
  }

  if (refreshed)
    *refreshed = true;
  return true;
}

bool build_stable_helper_payload_manifest(
    const std::filesystem::path &source_executable,
    const std::filesystem::path &stable_helper_path,
    std::vector<StableHelperPayloadEntry> *entries) {
  if (!entries) {
    return false;
  }
  entries->clear();

  std::error_code ec;
  if (!std::filesystem::is_regular_file(source_executable, ec)) {
    const std::string message =
        "Dedicated exv-helper.exe was not found in the package: " +
        source_executable.string();
    cli::print_error(message);
    exv::observability::LogFacade::error(message);
    return false;
  }

  entries->push_back({"exv-helper.exe", source_executable, stable_helper_path,
                      false});

  const std::filesystem::path stable_helper_directory =
      stable_helper_path.parent_path();
  for (const auto &asset_name : platform::stable_service_runtime_asset_names()) {
    const std::filesystem::path source =
        find_packaged_stable_runtime_asset(source_executable, asset_name);
    if (source.empty()) {
      const std::string message =
          "Required stable helper runtime payload was not found: " +
          asset_name + ". Checked package-relative locations next to " +
          source_executable.string();
      cli::print_error(message);
      exv::observability::LogFacade::error(message);
      return false;
    }
    entries->push_back(
        {asset_name, source, stable_helper_directory / asset_name, true});
  }

  return true;
}

bool verify_stable_helper_payload_manifest(
    const std::vector<StableHelperPayloadEntry> &entries,
    const std::filesystem::path &stable_helper_directory) {
  if (!verify_existing_stable_helper_directory(stable_helper_directory)) {
    return false;
  }
  if (!validate_stable_helper_directory_manifest(
          stable_helper_directory, stable_payload_allowlist_keys())) {
    return false;
  }

  for (const auto &entry : entries) {
    if (!verify_final_stable_helper_payload(entry.source, entry.target,
                                            entry.name)) {
      return false;
    }
  }
  return validate_stable_helper_directory_manifest(
      stable_helper_directory, stable_payload_allowlist_keys());
}

bool ensure_stable_helper_payload_manifest(
    const std::filesystem::path &source_executable,
    const std::filesystem::path &stable_helper_path, bool *helper_refreshed,
    bool *runtime_refreshed) {
  if (helper_refreshed) {
    *helper_refreshed = false;
  }
  if (runtime_refreshed) {
    *runtime_refreshed = false;
  }

  std::vector<StableHelperPayloadEntry> entries;
  if (!build_stable_helper_payload_manifest(source_executable,
                                            stable_helper_path, &entries)) {
    return false;
  }

  const std::filesystem::path stable_helper_directory =
      stable_helper_path.parent_path();
  if (!ensure_secure_stable_helper_directory(stable_helper_directory)) {
    return false;
  }
  if (!validate_stable_helper_directory_manifest(stable_helper_directory,
                                                stable_payload_allowlist_keys())) {
    return false;
  }

  for (const auto &entry : entries) {
    bool refreshed = false;
    if (!ensure_stable_helper_payload_asset(entry.source, entry.target,
                                            entry.name, &refreshed)) {
      return false;
    }
    if (entry.runtime) {
      if (runtime_refreshed && refreshed) {
        *runtime_refreshed = true;
      }
    } else if (helper_refreshed && refreshed) {
      *helper_refreshed = true;
    }
  }

  return verify_stable_helper_payload_manifest(entries,
                                               stable_helper_directory);
}

struct ServiceConfigSnapshot {
  std::string binary_path;
  std::string error_message;
  DWORD start_type = SERVICE_NO_CHANGE;
  bool valid = false;
};

ServiceConfigSnapshot query_service_config(SC_HANDLE service) {
  ServiceConfigSnapshot snapshot;
  DWORD bytes_needed = 0;
  if (QueryServiceConfigW(service, NULL, 0, &bytes_needed)) {
    snapshot.error_message = "QueryServiceConfigW unexpectedly returned an "
                             "empty service configuration.";
    return snapshot;
  }
  DWORD error = GetLastError();
  if (error != ERROR_INSUFFICIENT_BUFFER || bytes_needed == 0) {
    snapshot.error_message =
        "QueryServiceConfigW size query failed: " + windows_error_message(error);
    return snapshot;
  }

  std::vector<unsigned char> buffer(bytes_needed);
  auto *config = reinterpret_cast<QUERY_SERVICE_CONFIGW *>(buffer.data());
  if (!QueryServiceConfigW(service, config, bytes_needed, &bytes_needed) ||
      !config->lpBinaryPathName) {
    error = GetLastError();
    snapshot.error_message =
        "QueryServiceConfigW read failed: " + windows_error_message(error);
    return snapshot;
  }
  snapshot.binary_path = utf8_from_wide(config->lpBinaryPathName);
  snapshot.start_type = config->dwStartType;
  snapshot.valid = true;
  return snapshot;
}

bool wait_for_service_stopped(SC_HANDLE service, SERVICE_STATUS *status) {
  if (!status) {
    return false;
  }
  for (int i = 0; i < 50; ++i) {
    if (!QueryServiceStatus(service, status)) {
      return false;
    }
    if (status->dwCurrentState == SERVICE_STOPPED) {
      return true;
    }
    Sleep(100);
  }
  return false;
}

bool stop_running_stable_helper_service_before_refresh(
    SC_HANDLE service, const std::string &stable_helper_executable_path,
    ServiceConfigSnapshot *snapshot) {
  const ServiceConfigSnapshot service_config = query_service_config(service);
  if (snapshot) {
    *snapshot = service_config;
  }
  if (!service_config.valid) {
    exv::observability::LogFacade::error(
        "QueryServiceConfig failed before stable helper refresh: " +
        service_config.error_message);
    return false;
  }
  if (!platform::stable_service_binary_path_targets_executable(
          service_config.binary_path, stable_helper_executable_path)) {
    return true;
  }

  SERVICE_STATUS service_status = {};
  if (!QueryServiceStatus(service, &service_status)) {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::error(
        "QueryServiceStatus failed before stable helper refresh: " +
        win32_message(error));
    return false;
  }
  if (service_status.dwCurrentState == SERVICE_STOPPED) {
    return true;
  }

  cli::print_info(
      "Stopping helper service before refreshing stable helper payload...");
  if (!ControlService(service, SERVICE_CONTROL_STOP, &service_status)) {
    const DWORD error = GetLastError();
    if (error != ERROR_SERVICE_NOT_ACTIVE) {
      exv::observability::LogFacade::error(
          "ControlService stop failed before stable helper refresh: " +
          win32_message(error));
      return false;
    }
  }

  if (!wait_for_service_stopped(service, &service_status)) {
    exv::observability::LogFacade::error(
        "Helper service did not stop before stable helper refresh.");
    return false;
  }
  return true;
}

bool wait_for_service_deleted_or_marked(SC_HANDLE scm, const char *service_name,
                                        bool current_process_is_service) {
  if (current_process_is_service) {
    SC_HANDLE check = OpenServiceA(scm, service_name, SERVICE_QUERY_STATUS);
    if (!check) {
      DWORD err = GetLastError();
      return err == ERROR_SERVICE_DOES_NOT_EXIST ||
             err == ERROR_SERVICE_MARKED_FOR_DELETE;
    }
    CloseServiceHandle(check);
    return true;
  }

  for (int i = 0; i < 50; ++i) {
    SC_HANDLE check = OpenServiceA(scm, service_name, SERVICE_QUERY_STATUS);
    if (!check) {
      DWORD err = GetLastError();
      if (err == ERROR_SERVICE_DOES_NOT_EXIST ||
          err == ERROR_SERVICE_MARKED_FOR_DELETE) {
        return true;
      }
    } else {
      CloseServiceHandle(check);
    }
    Sleep(100);
  }
  return false;
}

// Terminate orphaned one-shot exv-helper.exe processes left behind by a
// crashed/killed previous instance, so a subsequent connect is not confused by
// a stale single-instance lock or pipe. The service helper process (if any)
// is excluded — the SCM owns its lifecycle.
void terminate_orphan_oneshot_helpers(DWORD service_pid) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return;
  }
  PROCESSENTRY32W entry;
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      if (_wcsicmp(entry.szExeFile, L"exv-helper.exe") != 0) {
        continue;
      }
      if (entry.th32ProcessID == GetCurrentProcessId()) {
        continue;
      }
      if (service_pid != 0 && entry.th32ProcessID == service_pid) {
        continue;
      }
      HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
      if (proc) {
        if (TerminateProcess(proc, 1)) {
          WaitForSingleObject(proc, 2000);
          exv::observability::LogFacade::info(
              "Uninstall: terminated orphaned one-shot helper pid=" +
              std::to_string(entry.th32ProcessID));
        }
        CloseHandle(proc);
      }
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
}

std::optional<DWORD> service_pid_for_orphan_cleanup(
    SC_HANDLE service, const std::string &operation) {
  SERVICE_STATUS_PROCESS process_status = {};
  DWORD bytes_needed = 0;
  if (QueryServiceStatusEx(
          service, SC_STATUS_PROCESS_INFO,
          reinterpret_cast<LPBYTE>(&process_status), sizeof(process_status),
          &bytes_needed)) {
    return process_status.dwProcessId;
  }

  const DWORD error = GetLastError();
  exv::observability::LogFacade::warn(
      operation + ": QueryServiceStatusEx failed before orphan one-shot "
                  "helper cleanup. Skipping orphan one-shot helper cleanup "
                  "because service pid is unknown: " +
      win32_message(error));
  return std::nullopt;
}

void cleanup_orphan_oneshot_helpers_for_service(SC_HANDLE service,
                                                const std::string &operation) {
  const std::optional<DWORD> service_pid =
      service_pid_for_orphan_cleanup(service, operation);
  if (!service_pid) {
    return;
  }
  terminate_orphan_oneshot_helpers(*service_pid);
}

} // namespace

int install_helper_service(const std::string &executable_path,
                           const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  if (!platform::check_root()) {
    cli::print_error(
        "Administrator privileges required. Please run from an elevated prompt.");
    return 1;
  }

  cli::print_info("Opening Service Control Manager...");
  SC_HANDLE hSCM =
      OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
  if (!hSCM) {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::error(
        "OpenSCManager failed: " + win32_message(error));
    return 1;
  }

  std::string exec_path = executable_path.empty() ? platform::get_executable_path()
                                                  : executable_path;
  if (exec_path.empty()) {
    exv::observability::LogFacade::error("Failed to resolve the exv executable path.");
    CloseServiceHandle(hSCM);
    return 1;
  }

  std::filesystem::path exec_fs_path(exec_path);
  const std::filesystem::path packaged_helper_path =
      exec_fs_path.parent_path() / "exv-helper.exe";
  const std::filesystem::path stable_helper_path =
      platform_config.default_service_binary_path;

  const std::string binary_path =
      "\"" + stable_helper_path.string() + "\" --service";
  SC_HANDLE hService = OpenServiceA(
      hSCM, platform_config.service_name,
      SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS |
          SERVICE_START | SERVICE_STOP);
  const bool service_exists = hService != NULL;
  if (service_exists) {
    cli::print_info(
        "Helper service is already installed. Refreshing service configuration...");
    if (!stop_running_stable_helper_service_before_refresh(
            hService, stable_helper_path.string(), nullptr)) {
      CloseServiceHandle(hService);
      CloseServiceHandle(hSCM);
      return 1;
    }
  } else {
    const DWORD open_error = GetLastError();
    if (open_error != ERROR_SERVICE_DOES_NOT_EXIST) {
      exv::observability::LogFacade::error("OpenService failed: " +
                                           win32_message(open_error));
      CloseServiceHandle(hSCM);
      return 1;
    }
  }

  bool helper_refreshed = false;
  bool runtime_refreshed = false;
  if (!ensure_stable_helper_payload_manifest(packaged_helper_path,
                                             stable_helper_path,
                                             &helper_refreshed,
                                             &runtime_refreshed)) {
    if (hService)
      CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 1;
  }

  if (!service_exists) {
    cli::print_info("Registering helper service...");
    hService = CreateServiceA(
        hSCM, platform_config.service_name, "EXV Helper",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL, binary_path.c_str(), NULL, NULL, NULL, NULL,
        NULL);
    if (!hService) {
      const DWORD error = GetLastError();
      exv::observability::LogFacade::error("CreateService failed: " +
                                           win32_message(error));
      CloseServiceHandle(hSCM);
      return 1;
    }
  } else {
    const ServiceConfigSnapshot service_config = query_service_config(hService);
    const bool binary_path_changed =
        !service_config.valid || service_config.binary_path != binary_path;
    const bool start_type_changed =
        !service_config.valid || service_config.start_type != SERVICE_AUTO_START;
    if (binary_path_changed || start_type_changed) {
      if (!ChangeServiceConfigA(hService, SERVICE_NO_CHANGE,
                                SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                binary_path.c_str(), NULL, NULL, NULL, NULL,
                                NULL, NULL)) {
        const DWORD error = GetLastError();
        exv::observability::LogFacade::error(
            "ChangeServiceConfig failed: " + win32_message(error));
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return 1;
      }
    }

    SERVICE_STATUS service_status = {};
    if (QueryServiceStatus(hService, &service_status) &&
        service_status.dwCurrentState != SERVICE_STOPPED &&
        (binary_path_changed || helper_refreshed || runtime_refreshed)) {
      cli::print_info(
          "Restarting helper service to apply refreshed helper runtime...");
      if (!ControlService(hService, SERVICE_CONTROL_STOP, &service_status)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
          exv::observability::LogFacade::warn(
              "ControlService stop failed before helper service restart: " +
              win32_message(error));
        }
      }
      for (int i = 0; i < 50; ++i) {
        if (!QueryServiceStatus(hService, &service_status) ||
            service_status.dwCurrentState == SERVICE_STOPPED) {
          break;
        }
        Sleep(100);
      }
    }
  }

  cleanup_orphan_oneshot_helpers_for_service(hService, "Install");

  cli::print_info("Starting helper service...");
  if (!StartService(hService, 0, NULL)) {
    DWORD err = GetLastError();
    if (err != ERROR_SERVICE_ALREADY_RUNNING) {
      exv::observability::LogFacade::error("StartService failed: " +
                                           win32_message(err));
      CloseServiceHandle(hService);
      CloseServiceHandle(hSCM);
      return 1;
    }
  }
  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);

  cli::print_info("Waiting for helper to become ready...");
  bool helper_ready = wait_until_ready(context, 50, 100000);

  cli::print_success("EXV helper service installed.");
  if (!helper_ready) {
    cli::print_warning(
        "Helper service was installed, but it has not responded yet.");
    cli::print_info("Run 'exv service status' again in a moment if needed.");
  }
  cli::print_info("You can now run 'exv' and 'exv stop' without elevation.");
  return 0;
}

int uninstall_helper_service(const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!hSCM)
    return 1;

  SC_HANDLE hService = OpenServiceA(
      hSCM, platform_config.service_name,
      SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (!hService) {
    std::cout << "Helper service is not installed.\n";
    CloseServiceHandle(hSCM);
    return 0;
  }

  SERVICE_STATUS_PROCESS process_status = {};
  DWORD bytes_needed = 0;
  bool current_process_is_service = false;
  if (QueryServiceStatusEx(
          hService, SC_STATUS_PROCESS_INFO,
          reinterpret_cast<LPBYTE>(&process_status),
          sizeof(process_status), &bytes_needed)) {
    current_process_is_service =
        process_status.dwProcessId == GetCurrentProcessId();
  }

  SERVICE_STATUS status = {};
  if (!current_process_is_service && QueryServiceStatus(hService, &status) &&
      status.dwCurrentState != SERVICE_STOPPED) {
    std::cout << "Stopping helper service...\n";
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    for (int i = 0; i < 100; ++i) {
      if (!QueryServiceStatus(hService, &status) ||
          status.dwCurrentState == SERVICE_STOPPED) {
        break;
      }
      Sleep(100);
    }
  }

  if (context.clear_session_state)
    context.clear_session_state();

  std::cout << "Deleting helper service registration...\n";
  if (!DeleteService(hService)) {
    DWORD err = GetLastError();
    if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
      exv::observability::LogFacade::error("DeleteService failed: " +
                                           win32_message(err));
      CloseServiceHandle(hService);
      CloseServiceHandle(hSCM);
      return 1;
    }
  }

  CloseServiceHandle(hService);

  const bool removed = wait_for_service_deleted_or_marked(
      hSCM, platform_config.service_name, current_process_is_service);

  CloseServiceHandle(hSCM);

  if (!removed) {
    exv::observability::LogFacade::error("Helper service is still registered after uninstall.");
    return 1;
  }

  // Full artifact cleanup: remove the stable helper binary and terminate any
  // orphaned one-shot exv-helper.exe processes left behind by a crashed/killed
  // previous instance, then re-probe to confirm the uninstall is complete. This
  // keeps the "not installed" state trustworthy so the backend resolver may
  // safely fall back to a one-shot helper on the next connect.
  {
    std::error_code remove_ec;
    const std::filesystem::path stable_helper_directory =
        std::filesystem::path(platform_config.default_service_binary_path)
            .parent_path();
    for (const auto &payload_name : platform::stable_service_payload_file_names()) {
      std::filesystem::remove(stable_helper_directory / payload_name, remove_ec);
      if (remove_ec) {
        exv::observability::LogFacade::warn(
            "Could not remove stable helper payload " + payload_name + ": " +
            remove_ec.message());
      }
      remove_ec.clear();
    }
    std::filesystem::remove(stable_helper_directory, remove_ec);
  }
  terminate_orphan_oneshot_helpers(
      current_process_is_service ? static_cast<DWORD>(GetCurrentProcessId())
                                 : process_status.dwProcessId);

  const ServiceStatusSnapshot after = current_service_status();
  if (after.installed) {
    exv::observability::LogFacade::error(
        "Uninstall completed but the service registration still reports "
        "installed.");
    return 1;
  }
  std::cout << "Helper service uninstalled.\n";
  return 0;
}

int repair_helper_service(const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  if (!platform::check_root()) {
    cli::print_error(
        "Administrator privileges required. Please run from an elevated prompt.");
    return 1;
  }

  std::string exec_path = platform::get_executable_path();
  if (exec_path.empty()) {
    exv::observability::LogFacade::error(
        "Failed to resolve the exv-helper executable path.");
    return 1;
  }

  const std::filesystem::path packaged_helper_path(exec_path);
  const std::filesystem::path stable_helper_path =
      platform_config.default_service_binary_path;
  const std::string binary_path =
      "\"" + stable_helper_path.string() + "\" --service";

  SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!hSCM) {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::error(
        "OpenSCManager failed: " + win32_message(error));
    return 1;
  }

  SC_HANDLE hService = OpenServiceA(
      hSCM, platform_config.service_name,
      SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP |
          SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
  if (!hService) {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::error("OpenService failed: " +
                                         win32_message(error));
    CloseServiceHandle(hSCM);
    cli::print_error("Helper service is not installed.");
    return 1;
  }

  if (!stop_running_stable_helper_service_before_refresh(
          hService, stable_helper_path.string(), nullptr)) {
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 1;
  }

  bool helper_refreshed = false;
  bool runtime_refreshed = false;
  if (!ensure_stable_helper_payload_manifest(packaged_helper_path,
                                             stable_helper_path,
                                             &helper_refreshed,
                                             &runtime_refreshed)) {
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 1;
  }

  const ServiceConfigSnapshot service_config = query_service_config(hService);
  const bool binary_path_changed =
      !service_config.valid || service_config.binary_path != binary_path;

  if (!ChangeServiceConfigA(hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                            SERVICE_NO_CHANGE, binary_path.c_str(), NULL, NULL,
                            NULL, NULL, NULL, NULL)) {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::error("ChangeServiceConfig failed: " +
                                         win32_message(error));
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return 1;
  }

  SERVICE_STATUS status = {};
  if (QueryServiceStatus(hService, &status) &&
      status.dwCurrentState != SERVICE_STOPPED &&
      (binary_path_changed || helper_refreshed || runtime_refreshed)) {
    cli::print_info("Restarting helper service to apply refreshed helper runtime...");
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
      const DWORD error = GetLastError();
      if (error != ERROR_SERVICE_NOT_ACTIVE) {
        exv::observability::LogFacade::warn(
            "ControlService stop failed before helper service repair restart: " +
            win32_message(error));
      }
    }
    for (int i = 0; i < 50; ++i) {
      if (!QueryServiceStatus(hService, &status) ||
          status.dwCurrentState == SERVICE_STOPPED) {
        break;
      }
      Sleep(100);
    }
  }

  cleanup_orphan_oneshot_helpers_for_service(hService, "Repair");

  bool service_running = false;
  if (QueryServiceStatus(hService, &status)) {
    service_running = status.dwCurrentState == SERVICE_RUNNING;
  } else {
    const DWORD error = GetLastError();
    exv::observability::LogFacade::warn(
        "QueryServiceStatus failed before helper service repair start: " +
        win32_message(error));
  }

  if (!service_running) {
    cli::print_info("Starting helper service...");
    if (!StartService(hService, 0, NULL)) {
      DWORD err = GetLastError();
      if (err != ERROR_SERVICE_ALREADY_RUNNING) {
        exv::observability::LogFacade::error("StartService failed: " +
                                             win32_message(err));
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return 1;
      }
      service_running = true;
    }
  }

  bool running = false;
  for (int i = 0; i < 50; ++i) {
    if (QueryServiceStatus(hService, &status) &&
        status.dwCurrentState == SERVICE_RUNNING) {
      running = true;
      break;
    }
    Sleep(100);
  }

  CloseServiceHandle(hService);
  CloseServiceHandle(hSCM);

  if (!running) {
    cli::print_error("Helper service did not reach the running state.");
    return 1;
  }

  cli::print_info("Waiting for helper to become ready...");
  if (!wait_until_ready(context, 50, 100000)) {
    cli::print_error("Helper service is running but did not respond.");
    return 1;
  }

  cli::print_success("EXV helper service repaired.");
  return 0;
}

int show_helper_service_status(const HelperServiceManagerContext &context) {
  const auto &platform_config = helper_platform_config();

  cli::print_header("EXV Service Status");

  SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
  if (!hSCM) {
    std::cout << "  Installed       : unknown (cannot open SCM)\n";
    return 1;
  }

  SC_HANDLE hService =
      OpenServiceA(hSCM, platform_config.service_name, SERVICE_QUERY_STATUS);
  bool installed = (hService != NULL);
  std::cout << "  Installed       : " << (installed ? "yes" : "no")
            << std::endl;

  bool available = false;
  if (installed) {
    SERVICE_STATUS status = {};
    QueryServiceStatus(hService, &status);
    std::cout << "  State           : "
              << (status.dwCurrentState == SERVICE_RUNNING ? "running"
                                                           : "stopped")
              << std::endl;
    if (status.dwCurrentState == SERVICE_RUNNING)
      available = wait_until_ready(context, 10, 100000);
    CloseServiceHandle(hService);
  }

  std::cout << "  Socket Ready    : " << (available ? "yes" : "no")
            << std::endl;
  print_runtime_status_if_available(context, available);
  std::cout << std::endl;

  CloseServiceHandle(hSCM);
  return 0;
}

} // namespace platform
} // namespace exv
