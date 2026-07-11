#pragma once

#include <map>
#include <string>
#include <vector>

namespace exv {
namespace vpn_engine {
namespace protocol {

enum class DtlsMode { Auto, Enabled, Disabled };

struct DtlsPolicyInput {
  DtlsMode mode = DtlsMode::Auto;
  bool gateway_advertised = false;
  bool backend_available = false;
  bool cooldown_active = false;
};

struct DtlsDecision {
  bool should_attempt = false;
  std::string reason;
};

struct DtlsCooldown {
  bool active = false;
  std::string reason;
};

class DtlsFailureHistory {
public:
  void record_failure(const std::string &network_key, const std::string &code);
  DtlsCooldown cooldown_for(const std::string &network_key) const;

private:
  std::map<std::string, std::vector<std::string>> failures_;
};

DtlsMode dtls_mode_from_legacy_disable(bool disable_dtls);
const char *dtls_mode_to_string(DtlsMode mode);
DtlsDecision decide_dtls(const DtlsPolicyInput &input);

} // namespace protocol
} // namespace vpn_engine
} // namespace exv
