#pragma once

#include <cstdint>
#include <vector>

namespace exv::setup::payload {

// Compress/decompress using Windows Cabinet Compression API (LZMS).
// Returns empty vector on failure.
std::vector<std::uint8_t> CompressLzms(const std::uint8_t *data, std::size_t size);
std::vector<std::uint8_t> DecompressLzms(const std::uint8_t *data,
                                         std::size_t compressed_size,
                                         std::size_t uncompressed_size);

}  // namespace exv::setup::payload
