#pragma once

#include "windows_setup_rust/payload/format.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace exv::setup::payload {

struct WriteOptions {
  Algorithm algorithm{Algorithm::Store};
};

// Builds an EXVP blob from every regular file under root (recursive).
// Paths inside the archive use forward slashes, relative to root.
// Returns empty vector on failure.
std::vector<std::uint8_t> BuildArchiveFromDirectory(const std::filesystem::path &root,
                                                    const WriteOptions &options = {});

bool WriteArchiveToFile(const std::filesystem::path &root,
                        const std::filesystem::path &out_file,
                        const WriteOptions &options = {});

}  // namespace exv::setup::payload
