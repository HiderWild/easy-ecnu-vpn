#include "windows_setup_rust/payload/archive_reader.hpp"

#include "windows_setup_rust/payload/crc32.hpp"
#include "windows_setup_rust/payload/win_compress.hpp"

#include <cctype>
#include <cstring>
#include <fstream>

namespace exv::setup::payload {
namespace {

bool ReadU16(const std::uint8_t *p, std::size_t size, std::size_t &offset, std::uint16_t &out) {
  if (offset + 2 > size) {
    return false;
  }
  out = static_cast<std::uint16_t>(p[offset] | (static_cast<std::uint16_t>(p[offset + 1]) << 8));
  offset += 2;
  return true;
}

bool ReadU32(const std::uint8_t *p, std::size_t size, std::size_t &offset, std::uint32_t &out) {
  if (offset + 4 > size) {
    return false;
  }
  out = static_cast<std::uint32_t>(p[offset]) |
        (static_cast<std::uint32_t>(p[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(p[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(p[offset + 3]) << 24);
  offset += 4;
  return true;
}

bool ReadU64(const std::uint8_t *p, std::size_t size, std::size_t &offset, std::uint64_t &out) {
  if (offset + 8 > size) {
    return false;
  }
  out = 0;
  for (int i = 0; i < 8; ++i) {
    out |= static_cast<std::uint64_t>(p[offset + static_cast<std::size_t>(i)])
           << (8 * i);
  }
  offset += 8;
  return true;
}

bool IsSafeRelativePath(const std::string &path) {
  if (path.empty() || path.front() == '/' || path.front() == '\\') {
    return false;
  }
  if (path.find("..") != std::string::npos) {
    return false;
  }
  if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':') {
    return false;
  }
  return true;
}

}  // namespace

bool ParseArchive(const std::uint8_t *data, std::size_t size, ArchiveView &out) {
  out = ArchiveView{};
  if (data == nullptr || size < 6 + 4 + 8 + 4) {
    return false;
  }
  if (std::memcmp(data, kMagic, 6) != 0) {
    return false;
  }

  std::size_t offset = 6;
  std::uint32_t flags = 0;
  std::uint32_t file_count = 0;
  if (!ReadU32(data, size, offset, flags) || !ReadU64(data, size, offset, out.uncompressed_total) ||
      !ReadU32(data, size, offset, file_count)) {
    return false;
  }
  out.algorithm = AlgorithmFromFlags(flags);
  out.files.reserve(file_count);

  for (std::uint32_t i = 0; i < file_count; ++i) {
    std::uint16_t path_len = 0;
    if (!ReadU16(data, size, offset, path_len)) {
      return false;
    }
    if (offset + path_len > size) {
      return false;
    }
    FileEntry entry;
    entry.path.assign(reinterpret_cast<const char *>(data + offset), path_len);
    offset += path_len;
    if (!IsSafeRelativePath(entry.path)) {
      return false;
    }
    if (!ReadU64(data, size, offset, entry.offset) ||
        !ReadU64(data, size, offset, entry.compressed_size) ||
        !ReadU64(data, size, offset, entry.uncompressed_size) ||
        !ReadU32(data, size, offset, entry.crc32)) {
      return false;
    }
    out.files.push_back(std::move(entry));
  }

  out.data_region_begin = offset;
  out.blob.assign(data, data + size);
  return true;
}

bool ParseArchive(const std::vector<std::uint8_t> &blob, ArchiveView &out) {
  return ParseArchive(blob.data(), blob.size(), out);
}

bool ExtractArchive(const ArchiveView &archive,
                    const std::filesystem::path &destination,
                    std::string *error_message,
                    const ProgressFn &progress) {
  auto fail = [&](const char *msg) {
    if (error_message != nullptr) {
      *error_message = msg;
    }
    return false;
  };

  if (archive.blob.empty()) {
    return fail("empty archive blob");
  }
  if (archive.algorithm != Algorithm::Store && archive.algorithm != Algorithm::WindowsLzms) {
    return fail("unsupported compression algorithm");
  }

  std::error_code ec;
  std::filesystem::create_directories(destination, ec);
  if (ec) {
    return fail("failed to create destination");
  }

  std::uint64_t written = 0;
  const auto total = archive.uncompressed_total;
  if (progress) {
    progress(0, total);
  }

  for (const auto &entry : archive.files) {
    if (!IsSafeRelativePath(entry.path)) {
      return fail("unsafe path in archive");
    }
    const auto data_off = archive.data_region_begin + static_cast<std::size_t>(entry.offset);
    if (archive.algorithm == Algorithm::Store &&
        entry.compressed_size != entry.uncompressed_size) {
      return fail("store entry size mismatch");
    }
    if (data_off + static_cast<std::size_t>(entry.compressed_size) > archive.blob.size()) {
      return fail("entry data out of range");
    }

    const auto *payload = archive.blob.data() + data_off;
    std::vector<std::uint8_t> plain;
    const std::uint8_t *plain_ptr = nullptr;
    std::size_t plain_size = 0;

    if (archive.algorithm == Algorithm::Store) {
      plain_ptr = payload;
      plain_size = static_cast<std::size_t>(entry.uncompressed_size);
    } else {
      plain = DecompressLzms(payload, static_cast<std::size_t>(entry.compressed_size),
                             static_cast<std::size_t>(entry.uncompressed_size));
      if (plain.size() != static_cast<std::size_t>(entry.uncompressed_size)) {
        return fail("decompress failed");
      }
      plain_ptr = plain.data();
      plain_size = plain.size();
    }

    const auto crc = Crc32(plain_ptr, plain_size);
    if (crc != entry.crc32) {
      return fail("crc mismatch");
    }

    const auto out_path = destination / std::filesystem::path(entry.path);
    std::filesystem::create_directories(out_path.parent_path(), ec);
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) {
      return fail("failed to open output file");
    }
    if (plain_size > 0) {
      out.write(reinterpret_cast<const char *>(plain_ptr),
                static_cast<std::streamsize>(plain_size));
      if (!out) {
        return fail("failed to write output file");
      }
    }
    written += entry.uncompressed_size;
    if (progress) {
      progress(written, total);
    }
  }
  return true;
}

}  // namespace exv::setup::payload
