#pragma once

#include "helper/common/helper_messages.hpp"
#include "helper/common/helper_protocol.hpp"
#include "helper/helper_handler.hpp"

#include <functional>
#include <memory>

namespace exv::helper {

enum class HelperLane {
  // Quick, read-only / lease management ops. Never blocks other lanes.
  Control,
  // Tunnel device + session-mutating ops. Serialized to avoid races on
  // managed network resources.
  Tunnel,
  // Periodic / heartbeat-style ops that must keep flowing while Tunnel ops
  // are in flight.
  Maintenance,
};

// Pick the lane an op belongs to. Mutually-exclusive tunnel ops go to Tunnel;
// heartbeat goes to Maintenance; everything else (hello/inspect/snapshot,
// lease lifecycle) goes to Control.
HelperLane lane_for_op(HelperOp op);

struct HelperLaneItem {
  HelperRequest request;
  HelperRequestContext context;
  std::function<HelperResponse(const HelperRequest &,
                               const HelperRequestContext &)>
      handler;
  std::function<void(HelperResponse)> respond;
};

class HelperLaneScheduler {
public:
  HelperLaneScheduler();
  ~HelperLaneScheduler();

  HelperLaneScheduler(const HelperLaneScheduler &) = delete;
  HelperLaneScheduler &operator=(const HelperLaneScheduler &) = delete;

  // Start the worker threads for every lane. Returns false if any worker
  // could not be started.
  bool start();

  // Stop all lanes. Pending items in each lane's queue are dropped; the
  // currently-running item is allowed to finish.
  void stop();

  // Enqueue an item on the lane appropriate for its op. Returns false if
  // the scheduler is stopped/not started.
  bool schedule(HelperLaneItem item);

private:
  struct LaneState;
  LaneState &state_for(HelperLane lane);

  std::unique_ptr<LaneState> control_;
  std::unique_ptr<LaneState> tunnel_;
  std::unique_ptr<LaneState> maintenance_;
};

} // namespace exv::helper
