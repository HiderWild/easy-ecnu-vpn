#pragma once
#include <cstdint>
#include <string>

namespace exv::helper {

enum class HelperOp : uint32_t {
    Hello = 1,
    StartSession = 2,
    PrepareTunnelDevice = 3,
    ApplyTunnelConfig = 4,
    Heartbeat = 5,
    Cleanup = 6,
    GetSnapshot = 7,
    Shutdown = 8,
    Inspect = 9,
    AcquireCoreLease = 10,
    KeepAlive = 11,
    ReleaseCoreLease = 12
};

enum class HelperMode : uint32_t {
    Transient = 1,
    Resident = 2
};

} // namespace exv::helper
