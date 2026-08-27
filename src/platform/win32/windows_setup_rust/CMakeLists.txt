# windows_setup_rust — isolated fork of the EXV custom Windows setup engine for
# the Rust product line (exv-core / exv-engine / exv-ui + wintun.dll).
#
# This is a SELF-CONTAINED CMake project: it does NOT include the EXV C++ product
# CMakeLists. It builds exactly two tools, copied from the deprecated C++ chain and
# adapted for the Rust trio:
#   - exv-setup (WIN32)          — the installer / uninstaller stub
#   - pack_setup_payload         — EXVP01 payload packer + PE resource injector
#
# Build:
#   cmake -S <this dir> -B <build dir> -G Ninja -DCMAKE_BUILD_TYPE=Release \
#         -DEXV_PRODUCT_VERSION=4.0.0
#   cmake --build <build dir> -j 4 --target exv-setup pack_setup_payload

cmake_minimum_required(VERSION 3.20)
project(exv-setup-rust LANGUAGES CXX RC)

set(EXV_PRODUCT_VERSION "4.0.0" CACHE STRING "EXV product version baked into the installer registry entry")

set(EXV_RUST_SETUP_PAYLOAD_SOURCES
  payload/crc32.cpp
  payload/win_compress.cpp
  payload/archive_reader.cpp
  payload/archive_writer.cpp
)

set(EXV_RUST_SETUP_ENGINE_SOURCES
  cli.cpp
  app_paths.cpp
  util/hidden_process.cpp
  process_control.cpp
  service_control.cpp
  elevate.cpp
  registry_install.cpp
  shortcuts.cpp
  progress_model.cpp
  uninstaller_copy.cpp
  install_engine.cpp
  uninstall_engine.cpp
  payload/embedded_payload.cpp
  ui/setup_window.cpp
  ui/icon_bitmaps.cpp
  ${EXV_RUST_SETUP_PAYLOAD_SOURCES}
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Version define: EXV_PRODUCT_VERSION_W=L"4.0.0"
set(EXV_PRODUCT_VERSION_DEF "EXV_PRODUCT_VERSION=L\"${EXV_PRODUCT_VERSION}\"")

# Self-contained assets so the fork builds independently of the worktree asset dir.
set(EXV_ICON_ICO "${CMAKE_CURRENT_SOURCE_DIR}/assets/icon.ico")
set(EXV_ICON_256 "${CMAKE_CURRENT_SOURCE_DIR}/assets/256x256.png")
configure_file(exv-setup.rc.in ${CMAKE_CURRENT_BINARY_DIR}/exv-setup.rc @ONLY)

# Sources include "windows_setup_rust/xxx.hpp", so the include root is the parent
# dir that contains the windows_setup_rust/ folder (src/platform/win32).
set(EXV_RUST_SETUP_INCLUDE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

add_executable(exv-setup WIN32
  main.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/exv-setup.rc
  ${EXV_RUST_SETUP_ENGINE_SOURCES}
)
target_include_directories(exv-setup PRIVATE
  ${EXV_RUST_SETUP_INCLUDE_ROOT}   # resolves windows_setup_rust/xxx.hpp includes
  ${CMAKE_CURRENT_SOURCE_DIR}      # resolves resource.hpp from the configured .rc
)
target_compile_definitions(exv-setup PRIVATE ${EXV_PRODUCT_VERSION_DEF})
target_link_libraries(exv-setup PRIVATE
  shell32 advapi32 ole32 uuid cabinet d2d1 dwrite windowscodecs dwmapi msimg32
)
set_target_properties(exv-setup PROPERTIES
  WIN32_EXECUTABLE TRUE
  OUTPUT_NAME "exv-setup"
)
if(MINGW)
  # Single-file installer runs on clean machines without MinGW runtime DLLs.
  target_link_options(exv-setup PRIVATE
    -municode
    -static
    -static-libgcc
    -static-libstdc++
  )
endif()

add_executable(pack_setup_payload
  tools/pack_setup_payload_main.cpp
  ${EXV_RUST_SETUP_PAYLOAD_SOURCES}
)
target_include_directories(pack_setup_payload PRIVATE ${EXV_RUST_SETUP_INCLUDE_ROOT})
target_link_libraries(pack_setup_payload PRIVATE cabinet)
if(MINGW)
  target_link_options(pack_setup_payload PRIVATE
    -static
    -static-libgcc
    -static-libstdc++
  )
endif()
