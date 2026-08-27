#include "windows_setup_rust/payload/embedded_payload.hpp"
#include "windows_setup_rust/resource.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace exv::setup::payload {

bool LoadEmbeddedPayload(ArchiveView &out, std::string *error) {
  auto fail = [&](const char *msg) {
    if (error) {
      *error = msg;
    }
    return false;
  };

  HRSRC res =
      FindResourceW(nullptr, MAKEINTRESOURCEW(kPayloadResourceId), (LPCWSTR)RT_RCDATA);
  if (res == nullptr) {
    return fail("payload resource not found");
  }
  HGLOBAL loaded = LoadResource(nullptr, res);
  if (loaded == nullptr) {
    return fail("LoadResource failed");
  }
  const DWORD size = SizeofResource(nullptr, res);
  const void *data = LockResource(loaded);
  if (data == nullptr || size == 0) {
    return fail("empty payload resource");
  }
  if (!ParseArchive(static_cast<const std::uint8_t *>(data), size, out)) {
    return fail("invalid EXVP payload");
  }
  return true;
}

bool ExtractEmbeddedPayloadTo(const std::filesystem::path &destination,
                              std::string *error,
                              const ProgressFn &progress) {
  ArchiveView view;
  if (!LoadEmbeddedPayload(view, error)) {
    return false;
  }
  return ExtractArchive(view, destination, error, progress);
}

}  // namespace exv::setup::payload
