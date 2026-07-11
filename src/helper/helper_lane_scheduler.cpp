#include "helper/helper_lane_scheduler.hpp"

#include "observability/log_facade.hpp"

#include <condition_variable>
#include <deque>
#include <exception>
#include <mutex>
#include <thread>
#include <utility>

namespace exv::helper {

HelperLane lane_for_op(HelperOp op) {
  switch (op) {
  case HelperOp::StartSession:
  case HelperOp::PrepareTunnelDevice:
  case HelperOp::ApplyTunnelConfig:
  case HelperOp::Cleanup:
  case HelperOp::Shutdown:
    return HelperLane::Tunnel;
  case HelperOp::Heartbeat:
    return HelperLane::Maintenance;
  case HelperOp::Hello:
  case HelperOp::GetSnapshot:
  case HelperOp::Inspect:
  case HelperOp::AcquireCoreLease:
  case HelperOp::KeepAlive:
  case HelperOp::ReleaseCoreLease:
    return HelperLane::Control;
  }
  return HelperLane::Control;
}

namespace {

HelperResponse handler_exception_response(const HelperRequest &request,
                                          const std::exception &error) {
  HelperResponse response;
  response.op = request.op;
  response.success = false;
  response.error_code = "handler_exception";
  response.error_message = error.what();
  return response;
}

HelperResponse unknown_exception_response(const HelperRequest &request) {
  HelperResponse response;
  response.op = request.op;
  response.success = false;
  response.error_code = "handler_exception";
  response.error_message = "Unhandled helper handler exception";
  return response;
}

} // namespace

struct HelperLaneScheduler::LaneState {
  explicit LaneState(HelperLane lane_value) : lane(lane_value) {}

  HelperLane lane;
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<HelperLaneItem> queue;
  std::thread worker;
  bool stopping = false;
  bool started = false;

  bool start() {
    std::lock_guard<std::mutex> lock(mutex);
    if (started) {
      return true;
    }
    stopping = false;
    started = true;
    worker = std::thread([this] { run(); });
    return true;
  }

  void stop() {
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (!started) {
        return;
      }
      stopping = true;
    }
    cv.notify_all();
    if (worker.joinable()) {
      worker.join();
    }
    std::lock_guard<std::mutex> lock(mutex);
    started = false;
  }

  bool schedule(HelperLaneItem item) {
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (stopping || !started) {
        return false;
      }
      queue.push_back(std::move(item));
    }
    cv.notify_one();
    return true;
  }

  void run() {
    for (;;) {
      HelperLaneItem item;
      {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return stopping || !queue.empty(); });
        if (queue.empty()) {
          if (stopping) {
            return;
          }
          continue;
        }
        item = std::move(queue.front());
        queue.pop_front();
      }

      HelperResponse response;
      try {
        response = item.handler(item.request, item.context);
      } catch (const std::exception &error) {
        response = handler_exception_response(item.request, error);
      } catch (...) {
        response = unknown_exception_response(item.request);
      }

      if (item.respond) {
        try {
          item.respond(std::move(response));
        } catch (const std::exception &error) {
          exv::observability::LogFacade::warn(
              std::string("HelperLaneScheduler: respond callback threw: ") +
              error.what());
        } catch (...) {
          exv::observability::LogFacade::warn(
              "HelperLaneScheduler: respond callback threw unknown exception");
        }
      }
    }
  }
};

HelperLaneScheduler::HelperLaneScheduler()
    : control_(std::make_unique<LaneState>(HelperLane::Control)),
      tunnel_(std::make_unique<LaneState>(HelperLane::Tunnel)),
      maintenance_(std::make_unique<LaneState>(HelperLane::Maintenance)) {}

HelperLaneScheduler::~HelperLaneScheduler() { stop(); }

bool HelperLaneScheduler::start() {
  return control_->start() && tunnel_->start() && maintenance_->start();
}

void HelperLaneScheduler::stop() {
  control_->stop();
  tunnel_->stop();
  maintenance_->stop();
}

bool HelperLaneScheduler::schedule(HelperLaneItem item) {
  return state_for(lane_for_op(item.request.op)).schedule(std::move(item));
}

HelperLaneScheduler::LaneState &
HelperLaneScheduler::state_for(HelperLane lane) {
  switch (lane) {
  case HelperLane::Tunnel:
    return *tunnel_;
  case HelperLane::Maintenance:
    return *maintenance_;
  case HelperLane::Control:
  default:
    return *control_;
  }
}

} // namespace exv::helper
