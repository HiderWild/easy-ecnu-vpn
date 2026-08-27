#pragma once

#include "windows_setup_rust/payload/archive_reader.hpp"

#include <filesystem>
#include <string>

namespace exv::setup::payload {

// Prefer windows_setup_rust/resource.hpp; keep numeric default for tools that only include this header.
#ifndef IDR_EXV_PAYLOAD
#define IDR_EXV_PAYLOAD 401
#endif
inline constexpr int kPayloadResourceId = IDR_EXV_PAYLOAD;

// Load embedded EXVP from the current module resources into ArchiveView.
bool LoadEmbeddedPayload(ArchiveView &out, std::string *error = nullptr);

// Extract embedded payload to destination with progress.
bool ExtractEmbeddedPayloadTo(const std::filesystem::path &destination,
                              std::string *error = nullptr,
                              const ProgressFn &progress = {});

}  // namespace exv::setup::payload
