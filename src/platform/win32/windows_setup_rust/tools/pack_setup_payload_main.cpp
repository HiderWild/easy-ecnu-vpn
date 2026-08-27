// pack_setup_payload — build EXVP blob from package dir and inject into setup PE.
//
// Usage:
//   pack_setup_payload --package-dir <dir> --stub <exv-setup.exe> --out <setup.exe>
//                       [--algo lzms|store]

#include "windows_setup_rust/payload/archive_writer.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void PrintUsage() {
  std::cerr
      << "Usage: pack_setup_payload --package-dir DIR --stub EXE --out EXE [--algo lzms|store]\n";
}

std::wstring ToWide(const std::string &s) {
  if (s.empty()) {
    return {};
  }
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring out(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
  return out;
}

bool ReadFile(const fs::path &path, std::vector<std::uint8_t> &out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  in.seekg(0, std::ios::end);
  const auto sz = in.tellg();
  if (sz < 0) {
    return false;
  }
  in.seekg(0, std::ios::beg);
  out.resize(static_cast<std::size_t>(sz));
  if (sz > 0) {
    in.read(reinterpret_cast<char *>(out.data()), sz);
  }
  return static_cast<bool>(in);
}

bool WriteFileBytes(const fs::path &path, const std::vector<std::uint8_t> &data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char *>(data.data()),
            static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(out);
}

// Resource type RCDATA, name 401 (IDR_EXV_PAYLOAD)
constexpr WORD kPayloadResourceId = 401;

bool InjectPayloadResource(const fs::path &stub,
                           const fs::path &out_path,
                           const std::vector<std::uint8_t> &payload) {
  std::error_code ec;
  fs::copy_file(stub, out_path, fs::copy_options::overwrite_existing, ec);
  if (ec) {
    std::cerr << "failed to copy stub: " << ec.message() << "\n";
    return false;
  }

  const auto out_w = out_path.wstring();
  HANDLE update = BeginUpdateResourceW(out_w.c_str(), FALSE);
  if (update == nullptr) {
    std::cerr << "BeginUpdateResource failed: " << GetLastError() << "\n";
    return false;
  }

  const BOOL ok = UpdateResourceW(update,
                                  (LPCWSTR)RT_RCDATA,
                                  MAKEINTRESOURCEW(kPayloadResourceId),
                                  MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                                  const_cast<std::uint8_t *>(payload.data()),
                                  static_cast<DWORD>(payload.size()));
  if (!ok) {
    std::cerr << "UpdateResource failed: " << GetLastError() << "\n";
    EndUpdateResourceW(update, TRUE);
    return false;
  }
  if (!EndUpdateResourceW(update, FALSE)) {
    std::cerr << "EndUpdateResource failed: " << GetLastError() << "\n";
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  std::string package_dir;
  std::string stub;
  std::string out;
  std::string algo = "lzms";

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto need = [&](std::string &dest) {
      if (i + 1 >= argc) {
        return false;
      }
      dest = argv[++i];
      return true;
    };
    if (a == "--package-dir") {
      if (!need(package_dir)) {
        PrintUsage();
        return 2;
      }
    } else if (a == "--stub") {
      if (!need(stub)) {
        PrintUsage();
        return 2;
      }
    } else if (a == "--out") {
      if (!need(out)) {
        PrintUsage();
        return 2;
      }
    } else if (a == "--algo") {
      if (!need(algo)) {
        PrintUsage();
        return 2;
      }
    } else if (a == "--help" || a == "-h") {
      PrintUsage();
      return 0;
    } else {
      std::cerr << "unknown arg: " << a << "\n";
      PrintUsage();
      return 2;
    }
  }

  if (package_dir.empty() || stub.empty() || out.empty()) {
    PrintUsage();
    return 2;
  }

  exv::setup::payload::WriteOptions opts;
  if (algo == "store") {
    opts.algorithm = exv::setup::payload::Algorithm::Store;
  } else if (algo == "lzms") {
    opts.algorithm = exv::setup::payload::Algorithm::WindowsLzms;
  } else {
    std::cerr << "unsupported algo: " << algo << "\n";
    return 2;
  }

  std::cout << "Packing " << package_dir << " (" << algo << ")...\n";
  const auto blob = exv::setup::payload::BuildArchiveFromDirectory(package_dir, opts);
  if (blob.empty()) {
    std::cerr << "failed to build EXVP archive\n";
    return 1;
  }
  std::cout << "EXVP size: " << blob.size() << " bytes\n";

  // Also write sibling .exvp for debugging.
  const fs::path out_path(out);
  WriteFileBytes(out_path.string() + ".exvp", blob);

  if (!InjectPayloadResource(stub, out_path, blob)) {
    return 1;
  }
  std::cout << "Wrote " << out << "\n";
  return 0;
}
