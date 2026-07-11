module;

#include <cstdint>

export module exv.helper.protocol;

export namespace exv::helper::protocol {

enum class HelperOp : std::uint32_t {
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
  ReleaseCoreLease = 12,
};

enum class HelperMode : std::uint32_t {
  Transient = 1,
  Resident = 2,
};

constexpr std::uint32_t helper_op_code(HelperOp op) noexcept {
  return static_cast<std::uint32_t>(op);
}

constexpr std::uint32_t helper_op_count() noexcept {
  return 12;
}

constexpr std::uint32_t helper_mode_code(HelperMode mode) noexcept {
  return static_cast<std::uint32_t>(mode);
}

constexpr bool helper_op_requires_session(HelperOp op) noexcept {
  switch (op) {
  case HelperOp::Hello:
  case HelperOp::StartSession:
  case HelperOp::GetSnapshot:
  case HelperOp::Inspect:
  case HelperOp::AcquireCoreLease:
  case HelperOp::KeepAlive:
  case HelperOp::ReleaseCoreLease:
    return false;
  case HelperOp::PrepareTunnelDevice:
  case HelperOp::ApplyTunnelConfig:
  case HelperOp::Heartbeat:
  case HelperOp::Cleanup:
  case HelperOp::Shutdown:
    return true;
  }
  return false;
}

} // namespace exv::helper::protocol
