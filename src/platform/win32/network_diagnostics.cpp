#include "platform/win32/network_diagnostics.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

namespace exv::platform::win32 {
namespace {

std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

#ifdef _WIN32
std::string narrow_wide(const wchar_t *value) {
  if (!value || *value == L'\0')
    return {};
  const int size =
      WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
  if (size <= 1)
    return {};
  std::string result(static_cast<std::size_t>(size), '\0');
  const int written = WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(),
                                          size, nullptr, nullptr);
  if (written <= 0)
    return {};
  result.resize(static_cast<std::size_t>(written));
  if (!result.empty() && result.back() == '\0')
    result.pop_back();
  return result;
}

std::string interface_type_name(unsigned int type) {
  switch (type) {
  case IF_TYPE_TUNNEL: return "tunnel";
  case IF_TYPE_SOFTWARE_LOOPBACK: return "loopback";
  case IF_TYPE_IEEE80211: return "wifi";
  case IF_TYPE_ETHERNET_CSMACD: return "ethernet";
  case IF_TYPE_PPP: return "ppp";
  default: return std::to_string(type);
  }
}
#endif

} // namespace

bool is_known_proxy_tun(const NetworkAdapterSnapshot &adapter) {
  const std::string name = lower_copy(adapter.name);
  const std::string type = lower_copy(adapter.interface_type);
  const bool proxy_named = name.find("clash") != std::string::npos ||
                           name.find("mihomo") != std::string::npos;
  const bool tun_like = name.find("tun") != std::string::npos ||
                        type.find("tun") != std::string::npos ||
                        type.find("tunnel") != std::string::npos;
  return proxy_named && tun_like;
}

std::vector<std::pair<std::string, std::string>>
network_adapter_route_snapshot_fields(
    const std::string &vpn_server,
    const NetworkAdapterSnapshotResult &snapshot_result) {
  std::vector<std::pair<std::string, std::string>> fields{
      {"proxy_tun_detected", "false"},
      {"vpn_server", vpn_server},
      {"adapter_count", std::to_string(snapshot_result.adapters.size())},
      {"snapshot_status", snapshot_result.ok ? "ok" : "error"},
  };
  if (!snapshot_result.ok) {
    fields.push_back(
        {"snapshot_error_code", std::to_string(snapshot_result.error_code)});
  }

  for (const auto &adapter : snapshot_result.adapters) {
    if (!is_known_proxy_tun(adapter))
      continue;
    fields[0].second = "true";
    fields.push_back({"proxy_tun_name", adapter.name});
    fields.push_back({"proxy_tun_interface_type", adapter.interface_type});
    fields.push_back({"proxy_tun_mtu", std::to_string(adapter.mtu)});
    fields.push_back(
        {"proxy_tun_interface_index", std::to_string(adapter.interface_index)});
    break;
  }

  return fields;
}

NetworkAdapterSnapshotResult snapshot_network_adapter_result() {
  NetworkAdapterSnapshotResult snapshot_result;
#ifdef _WIN32
  ULONG buffer_size = 15 * 1024;
  std::vector<unsigned char> buffer(buffer_size);
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                                      nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES *>(
                                          buffer.data()),
                                      &buffer_size);
  if (result == ERROR_BUFFER_OVERFLOW) {
    buffer.assign(buffer_size, 0);
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES,
                                  nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES *>(
                                      buffer.data()),
                                  &buffer_size);
  }
  if (result != NO_ERROR) {
    snapshot_result.ok = false;
    snapshot_result.error_code = result;
    return snapshot_result;
  }

  for (auto *addr = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data());
       addr != nullptr; addr = addr->Next) {
    NetworkAdapterSnapshot snapshot;
    snapshot.name = narrow_wide(addr->FriendlyName);
    if (snapshot.name.empty() && addr->AdapterName)
      snapshot.name = addr->AdapterName;
    snapshot.interface_type = interface_type_name(addr->IfType);
    snapshot.interface_index =
        addr->IfIndex != 0 ? static_cast<int>(addr->IfIndex)
                           : static_cast<int>(addr->Ipv6IfIndex);
    snapshot.mtu = static_cast<int>(addr->Mtu);
    snapshot_result.adapters.push_back(std::move(snapshot));
  }
#endif
  return snapshot_result;
}

std::vector<NetworkAdapterSnapshot> snapshot_network_adapters() {
  return snapshot_network_adapter_result().adapters;
}

} // namespace exv::platform::win32
