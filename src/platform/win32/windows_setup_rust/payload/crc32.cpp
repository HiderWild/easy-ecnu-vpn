#include "windows_setup_rust/payload/crc32.hpp"

namespace exv::setup::payload {
namespace {

std::uint32_t Table(std::uint32_t n) {
  std::uint32_t c = n;
  for (int k = 0; k < 8; ++k) {
    if (c & 1u) {
      c = 0xEDB88320u ^ (c >> 1);
    } else {
      c >>= 1;
    }
  }
  return c;
}

}  // namespace

std::uint32_t Crc32(const void *data, std::size_t size, std::uint32_t crc) {
  auto current = crc ^ 0xFFFFFFFFu;
  const auto *bytes = static_cast<const std::uint8_t *>(data);
  for (std::size_t i = 0; i < size; ++i) {
    current = Table((current ^ bytes[i]) & 0xFFu) ^ (current >> 8);
  }
  return current ^ 0xFFFFFFFFu;
}

}  // namespace exv::setup::payload
