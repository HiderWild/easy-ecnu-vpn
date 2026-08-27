#include "windows_setup_rust/payload/archive_writer.hpp"

#include "windows_setup_rust/payload/crc32.hpp"
#include "windows_setup_rust/payload/win_compress.hpp"

#include <algorithm>
#include <fstream>
#include <system_error>

namespace exv::setup::payload {
namespace {

void AppendU16(std::vector<std::uint8_t> &out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v & 0xFF));
  out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void AppendU32(std::vector<std::uint8_t> &out, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  }
}

void AppendU64(std::vector<std::uint8_t> &out, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
  }
}

std::string ToForwardRelative(const std::filesystem::path &root,
                              const std::filesystem::path &file) {
  auto rel = std::filesystem::relative(file, root).generic_string();
  return rel;
}

struct PendingFile {
  std::string path;
  std::vector<std::uint8_t> data;
  std::uint32_t crc{0};
};

bool ReadAll(const std::filesystem::path &path, std::vector<std::uint8_t> &out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  in.seekg(0, std::ios::end);
  const auto size = in.tellg();
  if (size < 0) {
    return false;
  }
  in.seekg(0, std::ios::beg);
  out.resize(static_cast<std::size_t>(size));
  if (size > 0) {
    in.read(reinterpret_cast<char *>(out.data()), size);
    if (!in) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::vector<std::uint8_t> BuildArchiveFromDirectory(const std::filesystem::path &root,
                                                    const WriteOptions &options) {
  std::error_code ec;
  if (!std::filesystem::is_directory(root, ec)) {
    return {};
  }

  if (options.algorithm != Algorithm::Store && options.algorithm != Algorithm::WindowsLzms) {
    return {};
  }

  std::vector<PendingFile> files;
  std::uint64_t total_uncompressed = 0;

  for (std::filesystem::recursive_directory_iterator it(
           root, std::filesystem::directory_options::skip_permission_denied, ec),
       end;
       it != end; it.increment(ec)) {
    if (ec) {
      return {};
    }
    if (!it->is_regular_file(ec)) {
      continue;
    }
    PendingFile item;
    item.path = ToForwardRelative(root, it->path());
    if (item.path.empty() || item.path == ".") {
      continue;
    }
    if (!ReadAll(it->path(), item.data)) {
      return {};
    }
    item.crc = Crc32(item.data.data(), item.data.size());
    total_uncompressed += item.data.size();
    files.push_back(std::move(item));
  }

  // Deterministic order for uninstall manifests / tests.
  std::sort(files.begin(), files.end(),
            [](const PendingFile &a, const PendingFile &b) { return a.path < b.path; });

  std::vector<std::uint8_t> out;
  out.insert(out.end(), kMagic, kMagic + 6);
  AppendU32(out, FlagsFromAlgorithm(options.algorithm));
  AppendU64(out, total_uncompressed);
  AppendU32(out, static_cast<std::uint32_t>(files.size()));

  // Reserve table then fill after data offsets known — two-pass.
  const std::size_t table_begin = out.size();
  std::size_t table_bytes = 0;
  for (const auto &f : files) {
    if (f.path.size() > 0xFFFF) {
      return {};
    }
    table_bytes += 2 + f.path.size() + 8 + 8 + 8 + 4;
  }
  out.resize(table_begin + table_bytes);

  std::vector<std::uint8_t> data_region;
  data_region.reserve(static_cast<std::size_t>(total_uncompressed));

  std::size_t table_cursor = table_begin;
  for (const auto &f : files) {
    const auto offset = static_cast<std::uint64_t>(data_region.size());
    std::vector<std::uint8_t> stored;
    if (options.algorithm == Algorithm::Store) {
      stored = f.data;
    } else {
      stored = CompressLzms(f.data.data(), f.data.size());
      if (stored.empty() && !f.data.empty()) {
        return {};
      }
    }
    data_region.insert(data_region.end(), stored.begin(), stored.end());

    const auto path_len = static_cast<std::uint16_t>(f.path.size());
    out[table_cursor++] = static_cast<std::uint8_t>(path_len & 0xFF);
    out[table_cursor++] = static_cast<std::uint8_t>((path_len >> 8) & 0xFF);
    for (char ch : f.path) {
      out[table_cursor++] = static_cast<std::uint8_t>(ch);
    }
    auto write_u64 = [&](std::uint64_t v) {
      for (int i = 0; i < 8; ++i) {
        out[table_cursor++] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
      }
    };
    auto write_u32 = [&](std::uint32_t v) {
      for (int i = 0; i < 4; ++i) {
        out[table_cursor++] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
      }
    };
    write_u64(offset);
    write_u64(static_cast<std::uint64_t>(stored.size()));
    write_u64(static_cast<std::uint64_t>(f.data.size()));
    write_u32(f.crc);
  }

  out.insert(out.end(), data_region.begin(), data_region.end());
  return out;
}

bool WriteArchiveToFile(const std::filesystem::path &root,
                        const std::filesystem::path &out_file,
                        const WriteOptions &options) {
  const auto blob = BuildArchiveFromDirectory(root, options);
  if (blob.empty()) {
    return false;
  }
  std::ofstream out(out_file, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char *>(blob.data()),
            static_cast<std::streamsize>(blob.size()));
  return static_cast<bool>(out);
}

}  // namespace exv::setup::payload
