#include "core/lifecycle/core_paths.hpp"

#include "runtime/runtime_context.hpp"

#include <cstdint>
#include <filesystem>

namespace exv::core::lifecycle {
namespace {

std::string state_leaf(const std::string& state_dir, const char* file_name) {
    return (std::filesystem::path(state_dir) / file_name).string();
}

#ifdef _WIN32
std::uint64_t fnv1a64(const std::string& value) {
    std::uint64_t hash = 1469598103934665603ull;
    for (unsigned char ch : value) {
        hash ^= static_cast<std::uint64_t>(ch);
        hash *= 1099511628211ull;
    }
    return hash;
}
#endif

} // namespace

std::string ipc_protocol_name() { return "ipc-v1"; }

std::string core_ipc_path() {
    return core_ipc_path(exv::runtime::paths().state_dir);
}

std::string core_ipc_path(const std::string& state_dir) {
#ifdef _WIN32
    return R"(\\.\pipe\exv-core-ipc-v1-)" +
           std::to_string(fnv1a64(core_lock_path(state_dir)));
#else
    return state_leaf(state_dir, "exv-core-ipc-v1.sock");
#endif
}

std::string core_lock_path() {
    return core_lock_path(exv::runtime::paths().state_dir);
}

std::string core_lock_path(const std::string& state_dir) {
    return state_leaf(state_dir, "exv-core-ipc-v1.lock");
}

std::string core_registry_path() {
    return core_registry_path(exv::runtime::paths().state_dir);
}

std::string core_registry_path(const std::string& state_dir) {
    return state_leaf(state_dir, "exv-core-ipc-v1.registry.json");
}

} // namespace exv::core::lifecycle
