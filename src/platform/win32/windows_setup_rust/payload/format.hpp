#pragma once

#include <cstdint>

namespace exv::setup::payload {

// On-disk magic: "EXVP01" (6 bytes, no NUL terminator in stream).
inline constexpr char kMagic[6] = {'E', 'X', 'V', 'P', '0', '1'};

enum class Algorithm : std::uint32_t {
  Store = 0,
  Lzma2 = 1,       // reserved (optional third_party later)
  Zstd = 2,        // reserved
  WindowsLzms = 3, // Windows Compression API COMPRESS_ALGORITHM_LZMS
};

// flags bits 0-7: Algorithm
inline constexpr std::uint32_t kFlagAlgoMask = 0xFFu;

inline Algorithm AlgorithmFromFlags(std::uint32_t flags) {
  return static_cast<Algorithm>(flags & kFlagAlgoMask);
}

inline std::uint32_t FlagsFromAlgorithm(Algorithm algo) {
  return static_cast<std::uint32_t>(algo) & kFlagAlgoMask;
}

}  // namespace exv::setup::payload
