#pragma once

#include "windows_setup_rust/payload/format.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace exv::setup::payload {

struct FileEntry {
  std::string path;  // relative, forward slashes
  std::uint64_t offset{0};
  std::uint64_t compressed_size{0};
  std::uint64_t uncompressed_size{0};
  std::uint32_t crc32{0};
};

struct ArchiveView {
  Algorithm algorithm{Algorithm::Store};
  std::uint64_t uncompressed_total{0};
  std::vector<FileEntry> files;
  // Full blob for data region access (owned copy when opened from bytes).
  std::vector<std::uint8_t> blob;
  std::size_t data_region_begin{0};
};

// Progress: bytes_written so far, total uncompressed (may be 0 if unknown).
using ProgressFn = std::function<void(std::uint64_t bytes_written, std::uint64_t total)>;

bool ParseArchive(const std::uint8_t *data, std::size_t size, ArchiveView &out);
bool ParseArchive(const std::vector<std::uint8_t> &blob, ArchiveView &out);

// Extracts all files under destination root. Creates parent directories.
bool ExtractArchive(const ArchiveView &archive,
                    const std::filesystem::path &destination,
                    std::string *error_message = nullptr,
                    const ProgressFn &progress = {});

}  // namespace exv::setup::payload
