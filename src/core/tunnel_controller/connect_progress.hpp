#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace exv::core {

enum class ConnectProgressStepState {
  Pending,
  Active,
  Done,
  Failed,
  Skipped
};

const char *connect_progress_state_wire_name(
    ConnectProgressStepState state) noexcept;

struct ConnectProgressStep {
  std::string key;
  std::string label;
  std::string description;
  ConnectProgressStepState state = ConnectProgressStepState::Pending;
  int priority = 0;
  std::string visual;
};

inline std::vector<ConnectProgressStep> default_connect_progress_steps() {
  return {
      {"intent", "Queue request",
       "Accept the connection request and prepare the secure tunnel plan.",
       ConnectProgressStepState::Pending, 10, "shield"},
      {"helper", "Prepare helper",
       "Start or attach to the privileged helper session.",
       ConnectProgressStepState::Pending, 20, "helper"},
      {"auth", "Authenticate",
       "Exchange credentials and obtain a VPN session.",
       ConnectProgressStepState::Pending, 30, "key"},
      {"server", "Connect server",
       "Establish the protected transport to the VPN gateway.",
       ConnectProgressStepState::Pending, 40, "server"},
      {"adapter", "Open adapter",
       "Create or attach to the local tunnel adapter.",
       ConnectProgressStepState::Pending, 50, "adapter"},
      {"routes", "Apply routes",
       "Install addresses, DNS, and route policy for the tunnel.",
       ConnectProgressStepState::Pending, 60, "routes"},
      {"packet", "Start packets",
       "Start packet forwarding through the tunnel device.",
       ConnectProgressStepState::Pending, 70, "packet"},
      {"check", "Verify tunnel",
       "Confirm that the tunnel is ready for application traffic.",
       ConnectProgressStepState::Pending, 80, "check"},
  };
}

struct ConnectProgress {
  std::string active_key;
  std::vector<ConnectProgressStep> steps = default_connect_progress_steps();
};

class ConnectProgressTracker {
public:
  ConnectProgressTracker();

  void reset();
  void start();
  bool mark_done(std::string_view key);
  bool mark_failed(std::string_view key);
  bool mark_skipped(std::string_view key);

  ConnectProgress snapshot() const;

private:
  bool set_state(std::string_view key, ConnectProgressStepState state);

  bool started_ = false;
  std::string failed_key_;
  std::vector<ConnectProgressStep> steps_;
};
} // namespace exv::core
