#include "windows_setup_rust/payload/win_compress.hpp"

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000  // Windows 10 — required for compressapi.h
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <compressapi.h>

namespace exv::setup::payload {
namespace {

struct CompressorCloser {
  COMPRESSOR_HANDLE handle{nullptr};
  ~CompressorCloser() {
    if (handle != nullptr) {
      CloseCompressor(handle);
    }
  }
};

struct DecompressorCloser {
  DECOMPRESSOR_HANDLE handle{nullptr};
  ~DecompressorCloser() {
    if (handle != nullptr) {
      CloseDecompressor(handle);
    }
  }
};

}  // namespace

std::vector<std::uint8_t> CompressLzms(const std::uint8_t *data, std::size_t size) {
  if (data == nullptr && size != 0) {
    return {};
  }
  CompressorCloser c;
  if (!CreateCompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &c.handle)) {
    return {};
  }

  // Prefer higher compression level when supported (ignored if unsupported).
  DWORD level = 1;
  SetCompressorInformation(c.handle, COMPRESS_INFORMATION_CLASS_LEVEL, &level, sizeof(level));

  SIZE_T compressed_size = 0;
  Compress(c.handle, size == 0 ? const_cast<void *>(static_cast<const void *>(""))
                               : const_cast<std::uint8_t *>(data),
           size, nullptr, 0, &compressed_size);
  if (compressed_size == 0) {
    compressed_size = size + size / 8 + 64;
  }

  std::vector<std::uint8_t> out(compressed_size);
  SIZE_T final_size = 0;
  void *src = size == 0 ? const_cast<void *>(static_cast<const void *>(""))
                        : const_cast<std::uint8_t *>(data);
  if (!Compress(c.handle, src, size, out.data(), out.size(), &final_size)) {
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && final_size > out.size()) {
      out.resize(final_size);
      if (!Compress(c.handle, src, size, out.data(), out.size(), &final_size)) {
        return {};
      }
    } else {
      return {};
    }
  }
  out.resize(final_size);
  return out;
}

std::vector<std::uint8_t> DecompressLzms(const std::uint8_t *data,
                                         std::size_t compressed_size,
                                         std::size_t uncompressed_size) {
  if ((data == nullptr && compressed_size != 0) || uncompressed_size > 512ull * 1024ull * 1024ull) {
    return {};
  }
  DecompressorCloser d;
  if (!CreateDecompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &d.handle)) {
    return {};
  }
  std::vector<std::uint8_t> out(uncompressed_size);
  SIZE_T final_size = 0;
  void *src = compressed_size == 0 ? const_cast<void *>(static_cast<const void *>(""))
                                   : const_cast<std::uint8_t *>(data);
  void *dst = uncompressed_size == 0 ? nullptr : out.data();
  if (!Decompress(d.handle, src, compressed_size, dst, out.size(), &final_size)) {
    return {};
  }
  if (final_size != uncompressed_size) {
    out.resize(final_size);
  }
  return out;
}

}  // namespace exv::setup::payload
