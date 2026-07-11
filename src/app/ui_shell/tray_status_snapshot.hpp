#pragma once

#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace exv::ui_shell {

struct TrayStatusSnapshot {
  bool connected = false;
  std::string username;
  std::chrono::seconds connected_duration{0};
};

inline std::string format_tray_duration(std::chrono::seconds duration) {
  if (duration <= std::chrono::seconds{0}) {
    return "-";
  }
  const auto total = duration.count();
  const auto hours = total / 3600;
  const auto minutes = (total % 3600) / 60;
  const auto seconds = total % 60;
  std::ostringstream out;
  out << std::setfill('0') << std::setw(2) << hours << ':' << std::setw(2)
      << minutes << ':' << std::setw(2) << seconds;
  return out.str();
}

inline std::vector<std::string>
tray_status_snapshot_menu_labels(const TrayStatusSnapshot &snapshot) {
  return {
      std::string("已连接: ") + (snapshot.connected ? "是" : "否"),
      std::string("用户名: ") +
          (snapshot.username.empty() ? std::string("未知") : snapshot.username),
      std::string("连接时长: ") +
          format_tray_duration(snapshot.connected_duration),
  };
}

} // namespace exv::ui_shell
