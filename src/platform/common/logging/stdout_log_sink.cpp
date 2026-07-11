#include "platform/common/logging/stdout_log_sink.hpp"

#include "observability/log_level.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <ostream>
#include <utility>

namespace exv::platform::logging {

std::mutex &stdout_stream_mutex() {
  static std::mutex mutex;
  return mutex;
}

StdoutLogSink::StdoutLogSink(std::ostream &out) : out_(out) {}

void StdoutLogSink::write(const exv::observability::LogEvent &event) {
  nlohmann::json fields = nlohmann::json::object();
  for (const auto &[key, value] : event.fields) {
    fields[key] = value;
  }

  auto timestamp = event.timestamp;
  if (timestamp == std::chrono::system_clock::time_point{}) {
    timestamp = std::chrono::system_clock::now();
  }

  nlohmann::json data = {
      {"level", exv::observability::to_string(event.level)},
      {"message", event.message},
      {"component", event.component},
      {"code", event.code},
      {"fields", fields},
      {"timestamp", timestamp.time_since_epoch().count()},
  };

  const nlohmann::json envelope = {
      {"event", "log"},
      {"data", std::move(data)},
  };

  std::lock_guard<std::mutex> lock(stdout_stream_mutex());
  out_ << envelope.dump() << '\n' << std::flush;
}

void StdoutLogSink::flush() {
  std::lock_guard<std::mutex> lock(stdout_stream_mutex());
  out_ << std::flush;
}

} // namespace exv::platform::logging
