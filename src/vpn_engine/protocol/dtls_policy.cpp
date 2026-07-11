#include "vpn_engine/protocol/dtls_policy.hpp"

#include <cstddef>

namespace exv {
namespace vpn_engine {
namespace protocol {

namespace {

constexpr std::size_t kMaxFailuresPerNetwork = 4;

} // namespace

DtlsMode dtls_mode_from_legacy_disable(bool disable_dtls) {
  return disable_dtls ? DtlsMode::Disabled : DtlsMode::Auto;
}

const char *dtls_mode_to_string(DtlsMode mode) {
  switch (mode) {
  case DtlsMode::Auto:
    return "auto";
  case DtlsMode::Enabled:
    return "enabled";
  case DtlsMode::Disabled:
    return "disabled";
  }
  return "auto";
}

DtlsDecision decide_dtls(const DtlsPolicyInput &input) {
  if (input.mode == DtlsMode::Disabled) {
    return {false, "disabled_by_user"};
  }
  if (!input.gateway_advertised) {
    return {false, "gateway_did_not_advertise_dtls"};
  }
  if (!input.backend_available) {
    return {false, "dtls_backend_unavailable"};
  }
  if (input.mode == DtlsMode::Auto && input.cooldown_active) {
    return {false, "auto_cooldown_active"};
  }
  return {true, input.mode == DtlsMode::Enabled ? "enabled_by_user"
                                                : "auto_attempt"};
}

void DtlsFailureHistory::record_failure(const std::string &network_key,
                                        const std::string &code) {
  std::vector<std::string> &failures = failures_[network_key];
  failures.push_back(code.empty() ? "dtls_failure" : code);
  if (failures.size() > kMaxFailuresPerNetwork)
    failures.erase(failures.begin(),
                   failures.begin() +
                       static_cast<std::ptrdiff_t>(failures.size() -
                                                   kMaxFailuresPerNetwork));
}

DtlsCooldown
DtlsFailureHistory::cooldown_for(const std::string &network_key) const {
  const auto it = failures_.find(network_key);
  if (it == failures_.end() || it->second.size() < 2)
    return {};

  DtlsCooldown cooldown;
  cooldown.active = true;
  cooldown.reason = "repeated_" + it->second.back();
  return cooldown;
}

} // namespace protocol
} // namespace vpn_engine
} // namespace exv
