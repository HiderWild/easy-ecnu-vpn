#pragma once

#include <cstddef>
#include <cstdint>

namespace exv::setup::payload {

// IEEE CRC-32 (poly 0xEDB88320), init/xor 0xFFFFFFFF — same class as zip/png.
std::uint32_t Crc32(const void *data, std::size_t size, std::uint32_t crc = 0);

}  // namespace exv::setup::payload
