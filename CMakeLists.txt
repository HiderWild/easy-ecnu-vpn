cmake_minimum_required(VERSION 3.28)
project(exv VERSION 3.3.7 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

enable_testing()
find_package(Python3 REQUIRED COMPONENTS Interpreter)

option(EXV_BUILD_UI_SHELL
    "Require real platform WebView shell SDK dependencies instead of stub host builds"
    OFF
)

set(EXV_DISTRIBUTION_ID "ecnu" CACHE STRING "Distribution profile id")
set(EXV_DISTRIBUTION_FILE
    "${CMAKE_SOURCE_DIR}/distribution/${EXV_DISTRIBUTION_ID}.json"
)
set(EXV_GENERATED_DISTRIBUTION_HEADER
    "${CMAKE_SOURCE_DIR}/src/generated/distribution_config.hpp"
)
set(EXV_GENERATED_DISTRIBUTION_TS
    "${CMAKE_SOURCE_DIR}/webui/src/generated/distribution.ts"
)

add_custom_command(
    OUTPUT
        "${EXV_GENERATED_DISTRIBUTION_HEADER}"
        "${EXV_GENERATED_DISTRIBUTION_TS}"
    COMMAND
        ${Python3_EXECUTABLE}
        "${CMAKE_SOURCE_DIR}/scripts/generate_distribution_config.py"
        --input "${EXV_DISTRIBUTION_FILE}"
        --cpp-output "${EXV_GENERATED_DISTRIBUTION_HEADER}"
        --ts-output "${EXV_GENERATED_DISTRIBUTION_TS}"
    DEPENDS
        "${EXV_DISTRIBUTION_FILE}"
        "${CMAKE_SOURCE_DIR}/scripts/generate_distribution_config.py"
    COMMENT "Generating EXV distribution config for ${EXV_DISTRIBUTION_ID}"
    VERBATIM
)

add_custom_target(exv-generate-distribution-config
    DEPENDS
        "${EXV_GENERATED_DISTRIBUTION_HEADER}"
        "${EXV_GENERATED_DISTRIBUTION_TS}"
)

# Release builds optimise for size and strip debug symbols. The MinGW
# toolchain we ship on Windows links against the gcc/g++ runtime DLLs, so
# stripping the binary itself gives the bulk of the savings (~3-4MB).
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Force UTF-8 source encoding for MSVC
if(MSVC)
    add_compile_options(/utf-8)
    add_compile_definitions(NOMINMAX)  # Prevent min/max macro conflicts
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(MSVC)
        add_compile_options(/O2 /GL)
        add_link_options(/LTCG /OPT:REF /OPT:ICF)
    else()
        add_compile_options(-Os -ffunction-sections -fdata-sections)
        if(WIN32)
            add_link_options(-Wl,--gc-sections -Wl,-s)
        elseif(APPLE)
            add_link_options(-Wl,-dead_strip)
        else()
            add_link_options(-Wl,--gc-sections -Wl,-s)
        endif()
    endif()
endif()

# Header-only nlohmann/json
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

set(EXV_PROTOCOL_SOURCES
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/protocol/data_channel.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
    src/vpn_engine/protocol/dtls_policy.cpp
    src/vpn_engine/protocol/dtls_transport.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/production_transport.cpp
    src/vpn_engine/protocol/session.cpp
    src/vpn_engine/protocol/tls_stream.cpp
    src/vpn_engine/protocol/url.cpp
)

set(EXV_DTLS_CHANNEL_BACKEND_SOURCE
    src/vpn_engine/dtls_channel_disabled.cpp
)

set(EXV_OBSERVABILITY_SOURCES
    src/observability/log_queue.cpp
    src/observability/log_service.cpp
    src/observability/log_facade.cpp
)

set(EXV_PLATFORM_LOGGING_SOURCES
    src/platform/common/logging/file_log_sink.cpp
    src/platform/common/logging/stdout_log_sink.cpp
    src/platform/common/logging/log_runtime.cpp
)

set(EXV_CORE_SOURCES
    src/core/config/config_manager.cpp
    src/core/config/config_initialization.cpp
    src/core/config/config_api.cpp
    src/core/config/config_persistence.cpp
    src/core/config/config_show.cpp
    src/core/config/config_set_value.cpp
    src/core/config/config_routes.cpp
    src/core/config/config_key.cpp
    src/core/config/config_wizard_common.cpp
    src/core/core_process.cpp
    src/platform/common/lifecycle/core_identity.cpp
    src/platform/common/lifecycle/core_paths.cpp
    src/platform/common/lifecycle/core_lock.cpp
    src/platform/common/lifecycle/core_registry.cpp
    src/platform/common/core_resolver.cpp
    src/core/pipe_ipc.cpp
    src/core/tunnel_controller/engine_event_bridge.cpp
    src/core/tunnel_controller/core_session_runner.cpp
    src/core/tunnel_controller/tunnel_controller.cpp
    src/core/tunnel_controller/tunnel_controller_state.cpp
    src/core/tunnel_controller/tunnel_controller_heartbeat.cpp
    src/core/tunnel_controller/tunnel_controller_connect.cpp
    src/core/tunnel_controller/tunnel_controller_disconnect.cpp
    src/core/tunnel_controller/tunnel_controller_reconnect.cpp
    src/core/tunnel_controller/tunnel_controller_events.cpp
    src/core/tunnel_controller/tunnel_controller_facade.cpp
    src/core/tunnel_controller/tunnel_controller_active.cpp
    src/core/tunnel_controller/connect_intent.cpp
    src/core/tunnel_controller/vpn_connect_job.cpp
    src/core/tunnel_controller/connect_pipeline.cpp
    src/core/tunnel_controller/connect_progress.cpp
    src/core/tunnel_controller/timing.cpp
    src/core/tunnel_controller/core_error_mapper.cpp
    src/core/tunnel_controller/native_engine_config_mapper.cpp
    src/core/tunnel_controller/reconnect_policy.cpp
    src/core/tunnel_controller/timer_scheduler.cpp
    src/core/rpc/app_rpc_dispatcher.cpp
    src/core/rpc/rpc_action_metadata.cpp
    src/core/rpc/lane_scheduler.cpp
    src/core/rpc/core_actions.cpp
    src/core/rpc/desktop_rpc_adapter.cpp
    src/core/rpc/vpn_actions.cpp
    src/core/rpc/config_actions.cpp
    src/core/rpc/service_actions.cpp
    src/core/rpc/route_actions.cpp
    src/core/rpc/log_actions.cpp
    src/core/rpc/maintenance_actions.cpp
    src/core/rpc/core_api_setup.cpp
    src/core/use_cases/config_use_cases.cpp
    src/core/use_cases/system_status_use_cases.cpp
    src/core/use_cases/connection_runtime_coordinator.cpp
    src/core/use_cases/tunnel_use_cases.cpp
    src/core/crypto/crypto.cpp
    src/helper/common/helper_connector.cpp
    src/helper/common/pipe_helper_client.cpp
    src/platform/common/backend_resolver.cpp
    src/platform/common/credential_store.cpp
    src/platform/common/dns_model.cpp
    src/platform/common/file_system.cpp
    src/platform/common/interface_stats.cpp
    src/platform/common/network_diagnostics.cpp
    src/platform/common/oneshot_bootstrap.cpp
    src/platform/common/packet_device_factory.cpp
    src/platform/common/process_utils.cpp
    src/platform/common/platform_network_ops.cpp
    src/platform/common/runtime_discovery.cpp
    src/platform/common/runtime_paths.cpp
    src/platform/common/helper_delegating_network_ops.cpp
    src/platform/common/proxy_tun_detector.cpp
    src/platform/common/route_model.cpp
    src/platform/common/status_models.cpp
    src/platform/common/runtime_status.cpp
    src/vpn_engine/native_engine.cpp
    src/vpn_engine/native_handshake_job.cpp
    ${EXV_PROTOCOL_SOURCES}
    src/vpn_engine/session_state.cpp
    src/core/app_api/app_api.cpp
    src/core/app_api/auth_interaction_coordinator.cpp
    src/core/app_api/desktop_action_registry.cpp
    src/core/app_api/desktop_config_actions.cpp
    src/core/app_api/desktop_json.cpp
    src/core/app_api/desktop_log_actions.cpp
    src/core/app_api/desktop_route_actions.cpp
    src/core/app_api/desktop_runtime_context.cpp
    src/core/app_api/desktop_status_presenter.cpp
    src/core/app_api/desktop_system_actions.cpp
    src/core/app_api/desktop_tunnel_host.cpp
    src/core/app_api/desktop_vpn_actions.cpp
    src/core/vpn/vpn.cpp
    src/core/vpn/vpn_runtime.cpp
    src/core/network/virtual_network_status.cpp
    src/runtime/runtime_context.cpp
    src/feedback/feedback.cpp
    src/core/connection/connection_attempt.cpp
    src/core/connection/tunnel_resource_lease.cpp
    src/common/diagnostics/logger.cpp
    src/common/diagnostics/log_event_bus.cpp
    src/common/diagnostics/log_renderer.cpp
    ${EXV_OBSERVABILITY_SOURCES}
    ${EXV_PLATFORM_LOGGING_SOURCES}
    src/cli/console.cpp
)

set(EXV_HELPER_RUNTIME_SOURCES
    src/helper/helper.cpp
    src/helper/helper_daemon_context.cpp
    src/helper/helper_lane_scheduler.cpp
    src/helper/helper_network_ops.cpp
    src/helper/helper_install_cli.cpp
    src/helper/common/helper_messages.cpp
    src/helper/runtime/helper_request_dispatcher.cpp
    src/helper/runtime/session_lease_manager.cpp
    src/helper/runtime/cleanup_registry.cpp
    src/helper/runtime/command_validator.cpp
    src/helper/runtime/helper_lifecycle_policy.cpp
    src/helper/runtime/helper_session_store.cpp
    src/helper/runtime/privileged_task_queue.cpp
    src/helper/helper_handler.cpp
)

set(EXV_CLI_TRANSPORT_SOURCES
    src/cli/pipe_client.cpp
)

set(EXV_CLI_FRONTEND_SOURCES
    src/cli/cli_main.cpp
    src/cli/cli_entrypoint.cpp
    src/cli/cli_commands.cpp
    src/cli/core_request_formatter.cpp
    src/cli/console.cpp
    ${EXV_CLI_TRANSPORT_SOURCES}
    src/platform/common/core_resolver.cpp
    src/platform/common/core_resolver_platform_deps.cpp
    src/platform/common/file_system.cpp
    src/platform/common/lifecycle/core_identity.cpp
    src/platform/common/lifecycle/core_lock.cpp
    src/platform/common/lifecycle/core_paths.cpp
    src/platform/common/lifecycle/core_registry.cpp
    src/platform/common/process_utils.cpp
    src/platform/common/runtime_paths.cpp
    src/runtime/runtime_context.cpp
    src/observability/log_facade.cpp
    src/observability/log_queue.cpp
    src/observability/log_service.cpp
    src/utils/strings.cpp
)

set(EXV_PLATFORM_SOURCES)
set(EXV_PLATFORM_LIBS)
set(EXV_PLATFORM_DEFINITIONS)

option(EXV_ENABLE_DTLS_BACKEND "Build native OpenSSL DTLS backend" OFF)
if(EXV_ENABLE_DTLS_BACKEND)
    find_package(OpenSSL 1.1.1 REQUIRED)
    set(EXV_DTLS_CHANNEL_BACKEND_SOURCE
        src/vpn_engine/dtls_channel_openssl.cpp
    )
    list(APPEND EXV_PLATFORM_LIBS OpenSSL::SSL OpenSSL::Crypto)
    list(APPEND EXV_PLATFORM_DEFINITIONS EXV_ENABLE_DTLS_BACKEND=1)
endif()
list(APPEND EXV_CORE_SOURCES ${EXV_DTLS_CHANNEL_BACKEND_SOURCE})

# Source files
set(SOURCES
    src/app/main.cpp
    src/cli/cli_entrypoint.cpp
    src/cli/cli_commands.cpp
    src/cli/core_request_formatter.cpp
    src/cli/pipe_client.cpp
    src/platform/common/core_resolver_platform_deps.cpp
)
find_package(Threads REQUIRED)

# Platform-specific dependencies
if(APPLE)
    # CommonCrypto links implicitly on macOS
    list(APPEND EXV_PLATFORM_DEFINITIONS EXV_PLATFORM_DARWIN=1)
    list(APPEND EXV_PLATFORM_LIBS "-framework Security" "-framework CoreFoundation")
    list(APPEND EXV_PLATFORM_SOURCES
        src/platform/darwin/helper_daemon.cpp
        src/platform/darwin/app_api_runtime_policy.cpp
        src/platform/darwin/crypto_backend.cpp
        src/platform/darwin/config_defaults.cpp
        src/platform/darwin/helper_client.cpp
        src/platform/darwin/helper_lifecycle.cpp
        src/platform/darwin/helper_platform.cpp
        src/platform/darwin/helper_service_manager.cpp
        src/platform/darwin/helper_single_instance.cpp
        src/platform/darwin/native_tls_stream.cpp
        src/platform/darwin/native_datagram_socket.cpp
        src/platform/darwin/native_packet_device.cpp
        src/platform/darwin/default_engine_deps.cpp
        src/platform/darwin/native_route_config.cpp
        src/platform/darwin/native_utun.cpp
        src/platform/darwin/platform_network_ops_darwin.cpp
        src/platform/darwin/oneshot_bootstrap.cpp
        src/platform/darwin/process_control.cpp
        src/platform/darwin/virtual_network_probe.cpp
        src/platform/darwin/path_utils.cpp
        src/platform/darwin/service_status.cpp
        src/platform/darwin/darwin_keychain_store.cpp
        src/platform/common/driver_status_stub.cpp
        src/platform/common/elevated_service_launcher.cpp
    )
    list(APPEND EXV_CLI_FRONTEND_SOURCES
        src/platform/darwin/crypto_backend.cpp
        src/platform/darwin/path_utils.cpp
    )
elseif(UNIX AND NOT APPLE)
    find_package(OpenSSL 1.1.1 REQUIRED)
    list(APPEND EXV_PLATFORM_DEFINITIONS EXV_PLATFORM_LINUX=1)
    list(APPEND EXV_PLATFORM_LIBS OpenSSL::SSL OpenSSL::Crypto)
    list(APPEND EXV_PLATFORM_SOURCES
        src/platform/linux/helper_daemon.cpp
        src/platform/linux/app_api_runtime_policy.cpp
        src/platform/linux/crypto_backend.cpp
        src/platform/linux/config_defaults.cpp
        src/platform/linux/helper_client.cpp
        src/platform/linux/helper_lifecycle.cpp
        src/platform/linux/helper_platform.cpp
        src/platform/linux/helper_service_manager.cpp
        src/platform/linux/helper_single_instance.cpp
        src/platform/linux/oneshot_bootstrap.cpp
        src/platform/linux/platform_network_ops_linux.cpp
        src/platform/linux/process_control.cpp
        src/platform/linux/virtual_network_probe.cpp
        src/platform/linux/path_utils.cpp
        src/platform/linux/default_engine_deps.cpp
        src/platform/common/service_status_linux.cpp
        src/platform/common/driver_status_stub.cpp
        src/platform/common/elevated_service_launcher.cpp
    )
    list(APPEND EXV_CLI_FRONTEND_SOURCES
        src/platform/linux/crypto_backend.cpp
        src/platform/linux/path_utils.cpp
    )
elseif(WIN32)
    # AES-256-CBC and CSPRNG come from Windows CNG (bcrypt) so we no longer
    # need OpenSSL on this platform. The ~7MB libssl/libcrypto DLLs can be
    # dropped from the desktop bundle entirely.
    list(APPEND EXV_PLATFORM_DEFINITIONS EXV_PLATFORM_WINDOWS=1)
    list(APPEND EXV_PLATFORM_LIBS bcrypt advapi32 iphlpapi ws2_32 secur32 crypt32 shell32 ole32)
    list(APPEND EXV_PLATFORM_SOURCES
        src/platform/win32/helper_daemon.cpp
        src/platform/win32/app_api_runtime_policy.cpp
        src/platform/win32/crypto_backend.cpp
        src/platform/win32/config_defaults.cpp
        src/platform/win32/helper_client.cpp
        src/platform/win32/helper_lifecycle.cpp
        src/platform/win32/helper_platform.cpp
        src/platform/win32/helper_service_manager.cpp
        src/platform/win32/helper_single_instance.cpp
        src/platform/win32/native_tls_stream.cpp
        src/platform/win32/native_datagram_socket.cpp
        src/platform/win32/native_packet_device.cpp
        src/platform/win32/default_engine_deps.cpp
        src/platform/win32/native_wintun.cpp
        src/platform/win32/native_ip_config.cpp
        src/platform/win32/network_diagnostics.cpp
        src/platform/win32/platform_network_ops_win32.cpp
        src/platform/win32/oneshot_bootstrap.cpp
        src/platform/win32/process_control.cpp
        src/platform/win32/virtual_network_probe.cpp
        src/platform/win32/path_utils.cpp
        src/platform/win32/service_status.cpp
        src/platform/win32/driver_status.cpp
        src/platform/win32/win_route_ops.cpp
        src/platform/win32/win_credential_store.cpp
        src/platform/win32/windows_strings.cpp
        src/platform/common/elevated_service_launcher.cpp
    )
    list(APPEND EXV_CLI_FRONTEND_SOURCES
        src/platform/win32/crypto_backend.cpp
        src/platform/win32/path_utils.cpp
    )
else()
    message(FATAL_ERROR "Unsupported platform. Supported: macOS, Linux, Windows.")
endif()

# This is the first native split toward the documented architecture.  The
# platform adapter files still live in this target because the current core
# sources call platform functions directly; C1/C2 will split those adapters
# behind cleaner interfaces.
add_library(exv-core STATIC
    ${EXV_CORE_SOURCES}
    ${EXV_PLATFORM_SOURCES}
)
add_dependencies(exv-core exv-generate-distribution-config)
target_include_directories(exv-core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(exv-core PUBLIC Threads::Threads ${EXV_PLATFORM_LIBS})
target_compile_definitions(exv-core PUBLIC
    EXV_VERSION="${PROJECT_VERSION}"
    ${EXV_PLATFORM_DEFINITIONS}
)

add_library(exv-helper-runtime STATIC
    ${EXV_HELPER_RUNTIME_SOURCES}
)
target_include_directories(exv-helper-runtime PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(exv-helper-runtime PUBLIC exv-core)
target_compile_definitions(exv-helper-runtime PUBLIC
    EXV_VERSION="${PROJECT_VERSION}"
    ${EXV_PLATFORM_DEFINITIONS}
)

add_library(exv-base-types-module STATIC)
target_sources(exv-base-types-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/base/modules/types.cppm
)
target_compile_features(exv-base-types-module PUBLIC cxx_std_20)
target_include_directories(exv-base-types-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-base-types-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-base-errors-module STATIC)
target_sources(exv-base-errors-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/base/modules/errors.cppm
)
target_compile_features(exv-base-errors-module PUBLIC cxx_std_20)
target_include_directories(exv-base-errors-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-base-errors-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-observability-log-module STATIC)
target_sources(exv-observability-log-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/observability/modules/log.cppm
)
target_compile_features(exv-observability-log-module PUBLIC cxx_std_20)
target_include_directories(exv-observability-log-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-observability-log-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-helper-protocol-module STATIC)
target_sources(exv-helper-protocol-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/helper/modules/helper_protocol.cppm
)
target_compile_features(exv-helper-protocol-module PUBLIC cxx_std_20)
set_target_properties(exv-helper-protocol-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-config-contract-module STATIC)
target_sources(exv-config-contract-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/config/modules/config_contract.cppm
)
target_compile_features(exv-config-contract-module PUBLIC cxx_std_20)
set_target_properties(exv-config-contract-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-core-tunnel-contract-module STATIC)
target_sources(exv-core-tunnel-contract-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/tunnel_controller/modules/tunnel_contract.cppm
)
target_compile_features(exv-core-tunnel-contract-module PUBLIC cxx_std_20)
set_target_properties(exv-core-tunnel-contract-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-core-tunnel-reconnect-module STATIC)
target_sources(exv-core-tunnel-reconnect-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/tunnel_controller/modules/tunnel_reconnect.cppm
)
target_compile_features(exv-core-tunnel-reconnect-module PUBLIC cxx_std_20)
target_include_directories(exv-core-tunnel-reconnect-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-core-tunnel-reconnect-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-core-tunnel-errors-module STATIC)
target_sources(exv-core-tunnel-errors-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/tunnel_controller/modules/tunnel_errors.cppm
)
target_compile_features(exv-core-tunnel-errors-module PUBLIC cxx_std_20)
target_include_directories(exv-core-tunnel-errors-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-core-tunnel-errors-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-core-tunnel-events-module STATIC)
target_sources(exv-core-tunnel-events-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/tunnel_controller/modules/tunnel_events.cppm
)
target_compile_features(exv-core-tunnel-events-module PUBLIC cxx_std_20)
target_include_directories(exv-core-tunnel-events-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-core-tunnel-events-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-core-tunnel-timing-module STATIC)
target_sources(exv-core-tunnel-timing-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/tunnel_controller/modules/tunnel_timing.cppm
)
target_compile_features(exv-core-tunnel-timing-module PUBLIC cxx_std_20)
target_include_directories(exv-core-tunnel-timing-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-core-tunnel-timing-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-core-tunnel-module STATIC)
target_sources(exv-core-tunnel-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/core/tunnel_controller/modules/tunnel.cppm
)
target_compile_features(exv-core-tunnel-module PUBLIC cxx_std_20)
target_include_directories(exv-core-tunnel-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(exv-core-tunnel-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_library(exv-utils-strings STATIC
    src/utils/strings.cpp
)
target_include_directories(exv-utils-strings PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_compile_features(exv-utils-strings PUBLIC cxx_std_20)

add_library(exv-utils-strings-module STATIC)
target_sources(exv-utils-strings-module
    PUBLIC
        FILE_SET CXX_MODULES
        FILES
            src/utils/modules/strings.cppm
)
target_compile_features(exv-utils-strings-module PUBLIC cxx_std_20)
target_include_directories(exv-utils-strings-module PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(exv-utils-strings-module PUBLIC
    exv-utils-strings
)
set_target_properties(exv-utils-strings-module PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

target_link_libraries(exv-core PUBLIC
    exv-utils-strings
)

add_executable(exv ${SOURCES})
# exv-core and exv-helper-runtime form a circular static-library
# dependency: core sources (pipe_helper_client, service_status,
# oneshot_bootstrap) reference helper messages and helper::is_available,
# while helper-runtime depends on core.  GNU ld resolves archives
# left-to-right by default, so the group wrapper tells it to make
# multiple passes.  MSVC and Apple ld64 handle this natively.
if(MINGW)
    target_link_libraries(exv PRIVATE
        "-Wl,--start-group"
        exv-helper-runtime
        exv-core
        "-Wl,--end-group"
    )
else()
    target_link_libraries(exv PRIVATE exv-helper-runtime exv-core)
endif()

add_executable(exv-cli ${EXV_CLI_FRONTEND_SOURCES})
add_dependencies(exv-cli exv-generate-distribution-config)
target_link_libraries(exv-cli PRIVATE Threads::Threads ${EXV_PLATFORM_LIBS})
target_compile_definitions(exv-cli PRIVATE
    EXV_VERSION="${PROJECT_VERSION}"
    ${EXV_PLATFORM_DEFINITIONS}
)

add_executable(exv-helper
    src/helper/helper_main.cpp
)
target_link_libraries(exv-helper PRIVATE exv-helper-runtime)
target_compile_definitions(exv-helper PRIVATE
    EXV_VERSION="${PROJECT_VERSION}"
)

# Pass version to source
target_compile_definitions(exv PRIVATE
    EXV_VERSION="${PROJECT_VERSION}"
)

# Embedded WebUI assets
#
# Build dependency chain: frontend must be built before the C++ build can
# succeed.  The custom command below runs scripts/embed_assets.py, which reads
# webui/dist/ (the Vite build output) and generates a build-tree webui_assets.hpp.
# If webui/dist/ does not exist, embed_assets.py will fail with instructions
# to build the frontend first:
#
#   cd webui && npm install && npm run build
#
# Then re-run the C++ build.  The full ordering is:
#   1. Frontend build (webui/dist/)
#   2. Native build    (this step �?consumes webui/dist/)
#   3. Desktop build   (optional �?packages native binary + Electron shell)
#
# WebUI removed �� Electron is the sole GUI entry point

add_executable(platform_status_models_test
    tests/platform_status_models_test.cpp
    src/platform/common/status_models.cpp
)

target_include_directories(platform_status_models_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME platform_status_models_test COMMAND platform_status_models_test)

add_executable(platform_network_ops_model_test
    tests/platform_network_ops_model_test.cpp
    src/platform/common/route_model.cpp
    src/platform/common/dns_model.cpp
)

target_include_directories(platform_network_ops_model_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_compile_definitions(platform_network_ops_model_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME platform_network_ops_model_test COMMAND platform_network_ops_model_test)

add_executable(feedback_test
    tests/feedback_test.cpp
    src/feedback/feedback.cpp
)

target_include_directories(feedback_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME feedback_test COMMAND feedback_test)

add_executable(runtime_status_native_test
    tests/runtime_status_native_test.cpp
    src/platform/common/runtime_status.cpp
    src/platform/common/status_models.cpp
)

if(APPLE)
    target_sources(runtime_status_native_test PRIVATE src/platform/darwin/config_defaults.cpp)
elseif(UNIX AND NOT APPLE)
    target_sources(runtime_status_native_test PRIVATE src/platform/linux/config_defaults.cpp)
elseif(WIN32)
    target_sources(runtime_status_native_test PRIVATE src/platform/win32/config_defaults.cpp)
endif()

target_include_directories(runtime_status_native_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(runtime_status_native_test PRIVATE
    exv-utils-strings
)

add_test(NAME runtime_status_native_test COMMAND runtime_status_native_test)

add_executable(backend_resolver_test
    tests/backend_resolver_test.cpp
    src/platform/common/backend_resolver.cpp
    src/platform/common/oneshot_bootstrap.cpp
    src/platform/common/status_models.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

target_include_directories(backend_resolver_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(backend_resolver_test PRIVATE Threads::Threads)

add_test(NAME backend_resolver_test COMMAND backend_resolver_test)

add_executable(native_session_state_test
    tests/native_session_state_test.cpp
    src/vpn_engine/session_state.cpp
)

target_include_directories(native_session_state_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_session_state_test COMMAND native_session_state_test)

add_executable(native_helper_session_test
    tests/native_helper_session_test.cpp
    tests/support/fake_helper.cpp
    src/helper/common/helper_messages.cpp
    src/helper/runtime/session_lease_manager.cpp
    src/helper/runtime/cleanup_registry.cpp
    src/helper/runtime/command_validator.cpp
    src/helper/runtime/helper_lifecycle_policy.cpp
    src/helper/runtime/helper_request_dispatcher.cpp
    src/helper/runtime/privileged_task_queue.cpp
    src/helper/helper_handler.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

target_include_directories(native_helper_session_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

target_compile_definitions(native_helper_session_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(native_helper_session_test PRIVATE exv-helper-runtime Threads::Threads)

add_test(NAME native_helper_session_test COMMAND native_helper_session_test)

add_executable(helper_service_cli_test
    tests/helper_service_cli_test.cpp
    src/helper/helper_install_cli.cpp)
target_include_directories(helper_service_cli_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src)
target_compile_features(helper_service_cli_test PRIVATE cxx_std_20)
target_link_libraries(helper_service_cli_test PRIVATE Threads::Threads)
add_test(NAME helper_service_cli_test COMMAND helper_service_cli_test)

add_executable(helper_exit_reason_test
    tests/helper_exit_reason_test.cpp)
target_include_directories(helper_exit_reason_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src)
target_compile_features(helper_exit_reason_test PRIVATE cxx_std_20)
add_test(NAME helper_exit_reason_test COMMAND helper_exit_reason_test)

add_executable(helper_single_instance_test
    tests/helper_single_instance_test.cpp)
target_include_directories(helper_single_instance_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src)
target_compile_features(helper_single_instance_test PRIVATE cxx_std_20)
target_link_libraries(helper_single_instance_test PRIVATE Threads::Threads)
target_sources(helper_single_instance_test PRIVATE
    $<$<PLATFORM_ID:Windows>:src/platform/win32/helper_single_instance.cpp>
    $<$<PLATFORM_ID:Darwin>:src/platform/darwin/helper_single_instance.cpp>
    $<$<PLATFORM_ID:Linux>:src/platform/linux/helper_single_instance.cpp>)
add_test(NAME helper_single_instance_test COMMAND helper_single_instance_test)

add_executable(helper_lane_scheduler_test
    tests/helper_lane_scheduler_test.cpp
    src/helper/helper_lane_scheduler.cpp
    src/helper/common/helper_messages.cpp
    ${EXV_OBSERVABILITY_SOURCES})
target_include_directories(helper_lane_scheduler_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src)
target_compile_features(helper_lane_scheduler_test PRIVATE cxx_std_20)
target_link_libraries(helper_lane_scheduler_test PRIVATE Threads::Threads)
add_test(NAME helper_lane_scheduler_test COMMAND helper_lane_scheduler_test)

add_executable(elevated_service_launcher_test
    tests/elevated_service_launcher_test.cpp
    src/platform/common/elevated_service_launcher.cpp)
target_include_directories(elevated_service_launcher_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src)
target_compile_features(elevated_service_launcher_test PRIVATE cxx_std_20)
target_link_libraries(elevated_service_launcher_test PRIVATE Threads::Threads)
add_test(NAME elevated_service_launcher_test COMMAND elevated_service_launcher_test)

add_executable(native_engine_contract_test
    tests/native_engine_contract_test.cpp
    src/vpn_engine/native_engine.cpp
    src/vpn_engine/native_handshake_job.cpp
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/protocol/data_channel.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
    ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
    src/vpn_engine/protocol/dtls_policy.cpp
    src/vpn_engine/protocol/dtls_transport.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/production_transport.cpp
    src/vpn_engine/protocol/session.cpp
    src/vpn_engine/protocol/tls_stream.cpp
    src/vpn_engine/protocol/url.cpp
    src/vpn_engine/session_state.cpp
)

if(APPLE)
    target_sources(native_engine_contract_test PRIVATE
        src/platform/darwin/config_defaults.cpp
        src/platform/darwin/default_engine_deps.cpp
        src/platform/darwin/native_tls_stream.cpp
        src/platform/darwin/native_datagram_socket.cpp
        src/platform/darwin/native_packet_device.cpp
        src/platform/darwin/native_route_config.cpp
        src/platform/darwin/native_utun.cpp
    )
elseif(UNIX AND NOT APPLE)
    target_sources(native_engine_contract_test PRIVATE
        src/platform/linux/config_defaults.cpp
        src/platform/linux/default_engine_deps.cpp
    )
elseif(WIN32)
    target_sources(native_engine_contract_test PRIVATE
        src/platform/win32/config_defaults.cpp
        src/platform/win32/default_engine_deps.cpp
        src/platform/win32/native_tls_stream.cpp
        src/platform/win32/native_datagram_socket.cpp
        src/platform/win32/native_packet_device.cpp
        src/platform/win32/native_wintun.cpp
        src/platform/win32/native_ip_config.cpp
        src/platform/win32/path_utils.cpp
        src/platform/common/file_system.cpp
        src/platform/common/process_utils.cpp
        src/platform/common/runtime_discovery.cpp
        src/platform/common/runtime_paths.cpp
        src/platform/win32/windows_strings.cpp
    )
endif()

target_include_directories(native_engine_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(native_engine_contract_test PRIVATE
    Threads::Threads
    exv-utils-strings
    ${EXV_PLATFORM_LIBS}
)

add_test(NAME native_engine_contract_test COMMAND native_engine_contract_test)

add_executable(native_handshake_job_test
    tests/native_handshake_job_test.cpp
    src/vpn_engine/native_engine.cpp
    src/vpn_engine/native_handshake_job.cpp
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/protocol/data_channel.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
    ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
    src/vpn_engine/protocol/dtls_policy.cpp
    src/vpn_engine/protocol/dtls_transport.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/production_transport.cpp
    src/vpn_engine/protocol/session.cpp
    src/vpn_engine/protocol/tls_stream.cpp
    src/vpn_engine/protocol/url.cpp
    src/vpn_engine/session_state.cpp
)

if(APPLE)
    target_sources(native_handshake_job_test PRIVATE
        src/platform/darwin/config_defaults.cpp
        src/platform/darwin/default_engine_deps.cpp
        src/platform/darwin/native_tls_stream.cpp
        src/platform/darwin/native_datagram_socket.cpp
        src/platform/darwin/native_packet_device.cpp
        src/platform/darwin/native_route_config.cpp
        src/platform/darwin/native_utun.cpp
    )
elseif(UNIX AND NOT APPLE)
    target_sources(native_handshake_job_test PRIVATE
        src/platform/linux/config_defaults.cpp
        src/platform/linux/default_engine_deps.cpp
    )
elseif(WIN32)
    target_sources(native_handshake_job_test PRIVATE
        src/platform/win32/config_defaults.cpp
        src/platform/win32/default_engine_deps.cpp
        src/platform/win32/native_tls_stream.cpp
        src/platform/win32/native_datagram_socket.cpp
        src/platform/win32/native_packet_device.cpp
        src/platform/win32/native_wintun.cpp
        src/platform/win32/native_ip_config.cpp
        src/platform/win32/path_utils.cpp
        src/platform/common/file_system.cpp
        src/platform/common/process_utils.cpp
        src/platform/common/runtime_discovery.cpp
        src/platform/common/runtime_paths.cpp
        src/platform/win32/windows_strings.cpp
    )
endif()

target_include_directories(native_handshake_job_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(native_handshake_job_test PRIVATE
    Threads::Threads
    exv-utils-strings
    ${EXV_PLATFORM_LIBS}
)

add_test(NAME native_handshake_job_test COMMAND native_handshake_job_test)

add_executable(native_event_sink_test
    tests/native_event_sink_test.cpp
    src/vpn_engine/event_sink.cpp
    src/vpn_engine/native_engine.cpp
    src/vpn_engine/native_handshake_job.cpp
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/protocol/data_channel.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
    ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
    src/vpn_engine/protocol/dtls_policy.cpp
    src/vpn_engine/protocol/dtls_transport.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/production_transport.cpp
    src/vpn_engine/protocol/session.cpp
    src/vpn_engine/protocol/tls_stream.cpp
    src/vpn_engine/protocol/url.cpp
    src/vpn_engine/session_state.cpp
)

if(APPLE)
    target_sources(native_event_sink_test PRIVATE
        src/platform/darwin/config_defaults.cpp
        src/platform/darwin/default_engine_deps.cpp
        src/platform/darwin/native_tls_stream.cpp
        src/platform/darwin/native_datagram_socket.cpp
        src/platform/darwin/native_packet_device.cpp
        src/platform/darwin/native_route_config.cpp
        src/platform/darwin/native_utun.cpp
    )
elseif(UNIX AND NOT APPLE)
    target_sources(native_event_sink_test PRIVATE
        src/platform/linux/config_defaults.cpp
        src/platform/linux/default_engine_deps.cpp
    )
elseif(WIN32)
    target_sources(native_event_sink_test PRIVATE
        src/platform/win32/config_defaults.cpp
        src/platform/win32/default_engine_deps.cpp
        src/platform/win32/native_tls_stream.cpp
        src/platform/win32/native_datagram_socket.cpp
        src/platform/win32/native_packet_device.cpp
        src/platform/win32/native_wintun.cpp
        src/platform/win32/native_ip_config.cpp
        src/platform/win32/path_utils.cpp
        src/platform/common/file_system.cpp
        src/platform/common/process_utils.cpp
        src/platform/common/runtime_discovery.cpp
        src/platform/common/runtime_paths.cpp
        src/platform/win32/windows_strings.cpp
    )
endif()

target_include_directories(native_event_sink_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(native_event_sink_test PRIVATE
    Threads::Threads
    exv-utils-strings
    ${EXV_PLATFORM_LIBS}
)

add_test(NAME native_event_sink_test COMMAND native_event_sink_test)

add_executable(proxy_tun_detector_test
    tests/proxy_tun_detector_test.cpp
    src/platform/common/proxy_tun_detector.cpp
)

target_include_directories(proxy_tun_detector_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME proxy_tun_detector_test COMMAND proxy_tun_detector_test)

add_executable(pipe_ipc_test
    tests/pipe_ipc_test.cpp
    src/platform/common/core_resolver_platform_deps.cpp
    ${EXV_CLI_TRANSPORT_SOURCES}
)

target_include_directories(pipe_ipc_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(pipe_ipc_test PRIVATE exv-core)

add_test(NAME pipe_ipc_test COMMAND pipe_ipc_test)

add_executable(app_api_runtime_policy_test
    tests/app_api_runtime_policy_test.cpp
)

if(APPLE)
    target_sources(app_api_runtime_policy_test PRIVATE src/platform/darwin/app_api_runtime_policy.cpp)
elseif(UNIX AND NOT APPLE)
    target_sources(app_api_runtime_policy_test PRIVATE src/platform/linux/app_api_runtime_policy.cpp)
elseif(WIN32)
    target_sources(app_api_runtime_policy_test PRIVATE src/platform/win32/app_api_runtime_policy.cpp)
endif()

target_include_directories(app_api_runtime_policy_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME app_api_runtime_policy_test COMMAND app_api_runtime_policy_test)

add_executable(native_packaging_policy_test
    tests/native_packaging_policy_test.cpp
)

target_compile_definitions(native_packaging_policy_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME native_packaging_policy_test COMMAND native_packaging_policy_test)

add_executable(native_only_cutover_contract_test
    tests/native_only_cutover_contract_test.cpp
)

target_compile_definitions(native_only_cutover_contract_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME native_only_cutover_contract_test COMMAND native_only_cutover_contract_test)

add_executable(repository_hygiene_test
    tests/repository_hygiene_test.cpp
)

target_compile_definitions(repository_hygiene_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME repository_hygiene_test COMMAND repository_hygiene_test)

add_executable(ui_shell_contract_test
    tests/ui_shell_contract_test.cpp
    src/app/ui_shell/close_preference.cpp
    src/app/ui_shell/host_bridge.cpp
    src/app/ui_shell/renderer_assets.cpp
    src/app/ui_shell/ui_shell_options.cpp
)

target_include_directories(ui_shell_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME ui_shell_contract_test COMMAND ui_shell_contract_test)

add_executable(ui_shell_core_rpc_client_test
    tests/ui_shell_core_rpc_client_test.cpp
    src/app/ui_shell/core_gateway.cpp
    src/app/ui_shell/core_rpc_client.cpp
    src/app/ui_shell/core_process_manager.cpp
    src/platform/common/core_resolver_platform_deps.cpp
    ${EXV_CLI_TRANSPORT_SOURCES}
)

target_include_directories(ui_shell_core_rpc_client_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ui_shell_core_rpc_client_test PRIVATE exv-core)

add_test(NAME ui_shell_core_rpc_client_test COMMAND ui_shell_core_rpc_client_test)

add_executable(ui_shell_runtime_test
    tests/ui_shell_runtime_test.cpp
    src/app/ui_shell/core_gateway.cpp
    src/app/ui_shell/core_rpc_client.cpp
    src/app/ui_shell/async_host_bridge.cpp
    src/app/ui_shell/host_bridge.cpp
    src/app/ui_shell/renderer_assets.cpp
    src/app/ui_shell/ui_shell_runtime.cpp
    src/app/ui_shell/ui_window.cpp
    ${EXV_CLI_TRANSPORT_SOURCES}
    src/platform/common/core_resolver_platform_deps.cpp
)

target_include_directories(ui_shell_runtime_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ui_shell_runtime_test PRIVATE exv-core)

add_test(NAME ui_shell_runtime_test COMMAND ui_shell_runtime_test)

add_executable(ui_shell_async_host_bridge_test
    tests/ui_shell_async_host_bridge_test.cpp
    src/app/ui_shell/core_rpc_client.cpp
    src/app/ui_shell/async_host_bridge.cpp
    src/app/ui_shell/host_bridge.cpp
    ${EXV_CLI_TRANSPORT_SOURCES}
    src/platform/common/core_resolver_platform_deps.cpp
)

target_include_directories(ui_shell_async_host_bridge_test PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ui_shell_async_host_bridge_test PRIVATE exv-core)

add_test(NAME ui_shell_async_host_bridge_test COMMAND ui_shell_async_host_bridge_test)

add_executable(ui_shell_cmake_policy_test
    tests/ui_shell_cmake_policy_test.cpp
)

target_compile_definitions(ui_shell_cmake_policy_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME ui_shell_cmake_policy_test COMMAND ui_shell_cmake_policy_test)

add_executable(ui_shell_main_wiring_test
    tests/ui_shell_main_wiring_test.cpp
)

target_compile_definitions(ui_shell_main_wiring_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME ui_shell_main_wiring_test COMMAND ui_shell_main_wiring_test)

if(WIN32)
    add_executable(win32_webview2_runtime_test
        tests/win32_webview2_runtime_test.cpp
        src/app/ui_shell/host_bridge.cpp
        src/platform/win32/ui_shell/webview2_host_win32.cpp
        src/platform/win32/ui_shell/ui_shell_single_instance_win32.cpp
        src/platform/win32/ui_shell/webview2_runtime_win32.cpp
    )

    target_include_directories(win32_webview2_runtime_test PRIVATE
        ${CMAKE_SOURCE_DIR}/src
    )

    target_compile_definitions(win32_webview2_runtime_test PRIVATE
        EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    )

    target_link_libraries(win32_webview2_runtime_test PRIVATE advapi32 urlmon shell32)

    add_test(NAME win32_webview2_runtime_test COMMAND win32_webview2_runtime_test)
endif()

if(APPLE)
    add_executable(darwin_wkwebview_runtime_test
        tests/darwin_wkwebview_runtime_test.cpp
        src/app/ui_shell/close_preference.cpp
        src/app/ui_shell/host_bridge.cpp
        src/platform/darwin/ui_shell/wk_webview_host_darwin.mm
        src/platform/darwin/ui_shell/ui_shell_single_instance_darwin.mm
    )

    target_include_directories(darwin_wkwebview_runtime_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    target_compile_definitions(darwin_wkwebview_runtime_test PRIVATE
        EXV_BUILD_UI_SHELL=1
        EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    )
    target_link_libraries(darwin_wkwebview_runtime_test PRIVATE
        "-framework Cocoa"
        "-framework WebKit"
    )

    add_test(NAME darwin_wkwebview_runtime_test COMMAND darwin_wkwebview_runtime_test)
endif()

if(UNIX AND NOT APPLE AND EXV_BUILD_UI_SHELL)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(WEBKITGTK REQUIRED webkit2gtk-4.1 gtk+-3.0)
endif()

if(UNIX AND NOT APPLE)
    add_executable(linux_webkitgtk_runtime_test
        tests/linux_webkitgtk_runtime_test.cpp
        src/app/ui_shell/host_bridge.cpp
        src/platform/linux/ui_shell/webkitgtk_host_linux.cpp
        src/platform/linux/ui_shell/ui_shell_single_instance_linux.cpp
    )

    target_include_directories(linux_webkitgtk_runtime_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )
    if(EXV_BUILD_UI_SHELL)
        target_compile_definitions(linux_webkitgtk_runtime_test PRIVATE
            EXV_BUILD_UI_SHELL=1
        )
        target_include_directories(linux_webkitgtk_runtime_test PRIVATE
            ${WEBKITGTK_INCLUDE_DIRS}
        )
        target_link_directories(linux_webkitgtk_runtime_test PRIVATE
            ${WEBKITGTK_LIBRARY_DIRS}
        )
        target_compile_options(linux_webkitgtk_runtime_test PRIVATE
            ${WEBKITGTK_CFLAGS_OTHER}
        )
        target_link_libraries(linux_webkitgtk_runtime_test PRIVATE
            ${WEBKITGTK_LIBRARIES}
        )
    endif()

    add_test(NAME linux_webkitgtk_runtime_test COMMAND linux_webkitgtk_runtime_test)
endif()

set(EXV_UI_COMMON_SOURCES
    src/app/ui_shell/ui_shell_main.cpp
    src/app/ui_shell/ui_window.cpp
    src/app/ui_shell/ui_shell_options.cpp
    src/app/ui_shell/renderer_assets.cpp
    src/app/ui_shell/close_preference.cpp
    src/app/ui_shell/host_bridge.cpp
    src/app/ui_shell/async_host_bridge.cpp
    src/app/ui_shell/core_gateway.cpp
    src/app/ui_shell/core_rpc_client.cpp
    src/app/ui_shell/core_process_manager.cpp
    src/app/ui_shell/ui_shell_runtime.cpp
    ${EXV_CLI_TRANSPORT_SOURCES}
    src/platform/common/core_resolver_platform_deps.cpp
)

set(EXV_UI_PLATFORM_SOURCES)
if(WIN32)
    if(EXV_BUILD_UI_SHELL)
        if(NOT DEFINED WEBVIEW2_SDK_DIR OR WEBVIEW2_SDK_DIR STREQUAL "")
            message(FATAL_ERROR "WEBVIEW2_SDK_DIR is required to build the Windows WebView2 shell")
        endif()

        set(WEBVIEW2_INCLUDE_DIR "${WEBVIEW2_SDK_DIR}/build/native/include")
        if(NOT EXISTS "${WEBVIEW2_INCLUDE_DIR}/WebView2.h")
            message(FATAL_ERROR "WEBVIEW2_SDK_DIR does not contain build/native/include/WebView2.h")
        endif()

        set(WEBVIEW2_LOADER_CANDIDATES
            "${WEBVIEW2_SDK_DIR}/build/native/x64/WebView2Loader.dll.lib"
            "${WEBVIEW2_SDK_DIR}/build/native/x64/WebView2LoaderStatic.lib"
            "${WEBVIEW2_SDK_DIR}/build/native/x86/WebView2Loader.dll.lib"
            "${WEBVIEW2_SDK_DIR}/build/native/x86/WebView2LoaderStatic.lib"
            "${WEBVIEW2_SDK_DIR}/build/native/arm64/WebView2Loader.dll.lib"
            "${WEBVIEW2_SDK_DIR}/build/native/arm64/WebView2LoaderStatic.lib"
        )
        set(WEBVIEW2_LOADER_LIBRARY "")
        foreach(_candidate IN LISTS WEBVIEW2_LOADER_CANDIDATES)
            if(EXISTS "${_candidate}")
                set(WEBVIEW2_LOADER_LIBRARY "${_candidate}")
                break()
            endif()
        endforeach()
        if(WEBVIEW2_LOADER_LIBRARY STREQUAL "")
            message(FATAL_ERROR "WEBVIEW2_SDK_DIR does not contain a WebView2Loader library")
        endif()

        set(WEBVIEW2_LOADER_DLL_CANDIDATES
            "${WEBVIEW2_SDK_DIR}/runtimes/win-x64/native/WebView2Loader.dll"
            "${WEBVIEW2_SDK_DIR}/runtimes/win-x86/native/WebView2Loader.dll"
            "${WEBVIEW2_SDK_DIR}/runtimes/win-arm64/native/WebView2Loader.dll"
            "${WEBVIEW2_SDK_DIR}/build/native/x64/WebView2Loader.dll"
            "${WEBVIEW2_SDK_DIR}/build/native/x86/WebView2Loader.dll"
            "${WEBVIEW2_SDK_DIR}/build/native/arm64/WebView2Loader.dll"
        )
        set(WEBVIEW2_LOADER_DLL "")
        foreach(_candidate IN LISTS WEBVIEW2_LOADER_DLL_CANDIDATES)
            if(EXISTS "${_candidate}")
                set(WEBVIEW2_LOADER_DLL "${_candidate}")
                break()
            endif()
        endforeach()
        if(WEBVIEW2_LOADER_DLL STREQUAL "")
            message(FATAL_ERROR "WEBVIEW2_SDK_DIR does not contain WebView2Loader.dll")
        endif()
    endif()
endif()

if(WIN32)
    set_source_files_properties(
        src/platform/win32/ui_shell/exv_ui_win32.rc
        PROPERTIES
        OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/src/platform/win32/ui_shell/exv_ui_win32.manifest"
    )

    list(APPEND EXV_UI_PLATFORM_SOURCES
        src/platform/win32/ui_shell/exv_ui_win32.rc
        src/platform/win32/ui_shell/webview2_host_win32.cpp
        src/platform/win32/ui_shell/webview2_runtime_win32.cpp
        src/platform/win32/ui_shell/ui_shell_single_instance_win32.cpp
    )
elseif(APPLE)
    list(APPEND EXV_UI_PLATFORM_SOURCES
        src/platform/darwin/ui_shell/wk_webview_host_darwin.mm
        src/platform/darwin/ui_shell/ui_shell_single_instance_darwin.mm
    )
elseif(UNIX)
    list(APPEND EXV_UI_PLATFORM_SOURCES
        src/platform/linux/ui_shell/webkitgtk_host_linux.cpp
        src/platform/linux/ui_shell/ui_shell_single_instance_linux.cpp
    )
endif()

add_executable(exv-ui
    ${EXV_UI_COMMON_SOURCES}
    ${EXV_UI_PLATFORM_SOURCES}
)

target_include_directories(exv-ui PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

if(WIN32)
    set_target_properties(exv-ui PROPERTIES WIN32_EXECUTABLE TRUE)
    target_link_libraries(exv-ui PRIVATE advapi32 urlmon shell32 exv-core)
    target_include_directories(exv-ui PRIVATE
        ${CMAKE_SOURCE_DIR}/src/platform/win32/ui_shell
        ${CMAKE_SOURCE_DIR}/assets/icons
    )
    if(EXV_BUILD_UI_SHELL)
        target_compile_definitions(exv-ui PRIVATE EXV_BUILD_UI_SHELL=1)
        target_include_directories(exv-ui PRIVATE "${WEBVIEW2_INCLUDE_DIR}")
        target_link_libraries(exv-ui PRIVATE "${WEBVIEW2_LOADER_LIBRARY}")
        add_custom_command(TARGET exv-ui POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${WEBVIEW2_LOADER_DLL}"
                    "$<TARGET_FILE_DIR:exv-ui>/WebView2Loader.dll"
        )
    endif()
elseif(APPLE AND EXV_BUILD_UI_SHELL)
    target_compile_definitions(exv-ui PRIVATE EXV_BUILD_UI_SHELL=1)
    target_link_libraries(exv-ui PRIVATE exv-core)
    target_link_libraries(exv-ui PRIVATE "-framework Cocoa" "-framework WebKit")
elseif(UNIX AND NOT APPLE AND EXV_BUILD_UI_SHELL)
    target_compile_definitions(exv-ui PRIVATE EXV_BUILD_UI_SHELL=1)
    target_include_directories(exv-ui PRIVATE ${WEBKITGTK_INCLUDE_DIRS})
    target_link_directories(exv-ui PRIVATE ${WEBKITGTK_LIBRARY_DIRS})
    target_compile_options(exv-ui PRIVATE ${WEBKITGTK_CFLAGS_OTHER})
    target_link_libraries(exv-ui PRIVATE exv-core)
    target_link_libraries(exv-ui PRIVATE ${WEBKITGTK_LIBRARIES})
endif()

add_executable(crypto_roundtrip_test
    tests/crypto_roundtrip_test.cpp
    src/core/crypto/crypto.cpp
    src/cli/console.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

if(APPLE)
    target_sources(crypto_roundtrip_test PRIVATE src/platform/darwin/crypto_backend.cpp)
elseif(UNIX AND NOT APPLE)
    target_sources(crypto_roundtrip_test PRIVATE src/platform/linux/crypto_backend.cpp)
    target_link_libraries(crypto_roundtrip_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
elseif(WIN32)
    target_sources(crypto_roundtrip_test PRIVATE src/platform/win32/crypto_backend.cpp)
    target_link_libraries(crypto_roundtrip_test PRIVATE bcrypt advapi32)
endif()

target_include_directories(crypto_roundtrip_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(crypto_roundtrip_test PRIVATE
    Threads::Threads
    exv-utils-strings
)

add_test(NAME crypto_roundtrip_test COMMAND crypto_roundtrip_test)

add_executable(native_url_test
    tests/native_url_test.cpp
    src/vpn_engine/protocol/url.cpp
    src/vpn_engine/protocol/http.cpp
)

target_include_directories(native_url_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_url_test COMMAND native_url_test)

add_executable(native_cstp_frame_test
    tests/native_cstp_frame_test.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/cstp.cpp
)

target_include_directories(native_cstp_frame_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_cstp_frame_test COMMAND native_cstp_frame_test)

add_executable(native_tls_stream_contract_test
    tests/native_tls_stream_contract_test.cpp
    src/vpn_engine/protocol/tls_stream.cpp
)

target_include_directories(native_tls_stream_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(native_tls_stream_contract_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME native_tls_stream_contract_test COMMAND native_tls_stream_contract_test)

add_executable(native_auth_parser_test
    tests/native_auth_parser_test.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/auth.cpp
)

target_include_directories(native_auth_parser_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_auth_parser_test COMMAND native_auth_parser_test)

add_executable(native_aggregate_auth_test
    tests/native_aggregate_auth_test.cpp
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/http.cpp
)

target_include_directories(native_aggregate_auth_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_aggregate_auth_test COMMAND native_aggregate_auth_test)

add_executable(native_protocol_session_test
    tests/native_protocol_session_test.cpp
    tests/support/fake_anyconnect_server.cpp
    src/vpn_engine/protocol/session.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/session_state.cpp
)

target_include_directories(native_protocol_session_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME native_protocol_session_test COMMAND native_protocol_session_test)

add_executable(native_production_transport_test
    tests/native_production_transport_test.cpp
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/protocol/data_channel.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
    ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
    src/vpn_engine/protocol/dtls_policy.cpp
    src/vpn_engine/protocol/dtls_transport.cpp
    src/vpn_engine/protocol/production_transport.cpp
)

target_include_directories(native_production_transport_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)
target_link_libraries(native_production_transport_test PRIVATE
    ${EXV_PLATFORM_LIBS}
)

add_test(NAME native_production_transport_test COMMAND native_production_transport_test)

add_executable(native_dtls_transport_test
    tests/native_dtls_transport_test.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/aggregate_auth.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/protocol/data_channel.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
    ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
    src/vpn_engine/protocol/dtls_policy.cpp
    src/vpn_engine/protocol/dtls_transport.cpp
    src/vpn_engine/protocol/production_transport.cpp
    src/vpn_engine/protocol/url.cpp
)

target_include_directories(native_dtls_transport_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)
target_link_libraries(native_dtls_transport_test PRIVATE
    ${EXV_PLATFORM_LIBS}
)

add_test(NAME native_dtls_transport_test COMMAND native_dtls_transport_test)

add_executable(native_dtls_offer_test
    tests/native_dtls_offer_test.cpp
    src/vpn_engine/protocol/dtls_offer.cpp
)

target_include_directories(native_dtls_offer_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_dtls_offer_test COMMAND native_dtls_offer_test)

add_executable(native_dtls_policy_test
    tests/native_dtls_policy_test.cpp
    src/vpn_engine/protocol/dtls_policy.cpp
)

target_include_directories(native_dtls_policy_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_dtls_policy_test COMMAND native_dtls_policy_test)

add_executable(native_dtls_data_channel_test
    tests/native_dtls_data_channel_test.cpp
    src/vpn_engine/protocol/data_channel.cpp
)

target_include_directories(native_dtls_data_channel_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_dtls_data_channel_test COMMAND native_dtls_data_channel_test)

add_executable(native_datagram_socket_contract_test
    tests/native_datagram_socket_contract_test.cpp
)

if(WIN32)
    target_sources(native_datagram_socket_contract_test PRIVATE
        src/platform/win32/native_datagram_socket.cpp
    )
    target_link_libraries(native_datagram_socket_contract_test PRIVATE ws2_32)
elseif(APPLE)
    target_sources(native_datagram_socket_contract_test PRIVATE
        src/platform/darwin/native_datagram_socket.cpp
    )
elseif(UNIX)
    target_sources(native_datagram_socket_contract_test PRIVATE
        src/platform/linux/native_datagram_socket.cpp
    )
endif()

target_include_directories(native_datagram_socket_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(native_datagram_socket_contract_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME native_datagram_socket_contract_test COMMAND native_datagram_socket_contract_test)

add_executable(native_gateway_route_diagnostics_test
    tests/native_gateway_route_diagnostics_test.cpp
    src/platform/win32/network_diagnostics.cpp
)

target_include_directories(native_gateway_route_diagnostics_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

if(WIN32)
    target_link_libraries(native_gateway_route_diagnostics_test PRIVATE
        iphlpapi
        ws2_32
    )
endif()

add_test(NAME native_gateway_route_diagnostics_test
         COMMAND native_gateway_route_diagnostics_test)

add_executable(native_dtls_channel_test
    tests/native_dtls_channel_test.cpp
    src/vpn_engine/protocol/dtls_channel.cpp
    ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
)

target_include_directories(native_dtls_channel_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(native_dtls_channel_test PRIVATE
    ${EXV_PLATFORM_DEFINITIONS}
)

add_test(NAME native_dtls_channel_test COMMAND native_dtls_channel_test)

if(EXV_ENABLE_DTLS_BACKEND)
    target_link_libraries(native_dtls_channel_test PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    if(WIN32 AND OPENSSL_ROOT_DIR)
        set_tests_properties(native_dtls_channel_test PROPERTIES
            ENVIRONMENT_MODIFICATION
                "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin"
        )
    endif()

    add_executable(native_dtls_channel_openssl_test
        tests/native_dtls_channel_test.cpp
        src/vpn_engine/protocol/dtls_channel.cpp
        ${EXV_DTLS_CHANNEL_BACKEND_SOURCE}
    )

    target_include_directories(native_dtls_channel_openssl_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_compile_definitions(native_dtls_channel_openssl_test PRIVATE
        ${EXV_PLATFORM_DEFINITIONS}
    )

    target_link_libraries(native_dtls_channel_openssl_test PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )

    add_test(NAME native_dtls_channel_openssl_test
             COMMAND native_dtls_channel_openssl_test)
    if(WIN32 AND OPENSSL_ROOT_DIR)
        set_tests_properties(native_dtls_channel_openssl_test PROPERTIES
            ENVIRONMENT_MODIFICATION
                "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin"
        )
    endif()
endif()

add_executable(native_fake_anyconnect_server_test
    tests/native_fake_anyconnect_server_test.cpp
    tests/support/fake_anyconnect_server.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/cstp.cpp
    src/vpn_engine/session_state.cpp
)

target_include_directories(native_fake_anyconnect_server_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME native_fake_anyconnect_server_test COMMAND native_fake_anyconnect_server_test)

if(WIN32)
    add_executable(win32_native_wintun_test
        tests/win32_native_wintun_test.cpp
        src/platform/win32/native_wintun.cpp
    )

    target_include_directories(win32_native_wintun_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(win32_native_wintun_test PRIVATE iphlpapi)

    add_test(NAME win32_native_wintun_test COMMAND win32_native_wintun_test)

    add_executable(win32_driver_status_test
        tests/win32_driver_status_test.cpp
        src/platform/win32/driver_status.cpp
        src/platform/win32/app_api_runtime_policy.cpp
        src/platform/common/process_utils.cpp
        src/utils/strings.cpp
    )

    target_include_directories(win32_driver_status_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    add_test(NAME win32_driver_status_test COMMAND win32_driver_status_test)

    add_executable(win32_native_ip_config_test
        tests/win32_native_ip_config_test.cpp
        src/platform/win32/native_ip_config.cpp
    )

    target_include_directories(win32_native_ip_config_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(win32_native_ip_config_test PRIVATE iphlpapi ws2_32)

    add_test(NAME win32_native_ip_config_test COMMAND win32_native_ip_config_test)

    add_executable(win32_native_packet_device_test
        tests/win32_native_packet_device_test.cpp
        src/platform/win32/native_packet_device.cpp
        src/platform/win32/native_wintun.cpp
        src/platform/win32/native_ip_config.cpp
    )

    target_include_directories(win32_native_packet_device_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_compile_definitions(win32_native_packet_device_test PRIVATE
        EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
    )

    target_link_libraries(win32_native_packet_device_test PRIVATE iphlpapi ws2_32)

    add_test(NAME win32_native_packet_device_test COMMAND win32_native_packet_device_test)

    add_executable(win32_native_tls_stream_test
        tests/win32_native_tls_stream_test.cpp
        src/platform/win32/native_tls_stream.cpp
    )

    target_include_directories(win32_native_tls_stream_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(win32_native_tls_stream_test PRIVATE ws2_32 secur32 crypt32)

    add_test(NAME win32_native_tls_stream_test COMMAND win32_native_tls_stream_test)
endif()

if(APPLE)
    add_executable(darwin_native_utun_test
        tests/darwin_native_utun_test.cpp
        src/platform/darwin/native_utun.cpp
    )

    target_include_directories(darwin_native_utun_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    add_test(NAME darwin_native_utun_test COMMAND darwin_native_utun_test)
endif()

if(APPLE)
    add_executable(darwin_native_route_config_test
        tests/darwin_native_route_config_test.cpp
        src/platform/darwin/native_route_config.cpp
    )

    target_include_directories(darwin_native_route_config_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    add_test(NAME darwin_native_route_config_test COMMAND darwin_native_route_config_test)

    add_executable(darwin_native_packet_device_test
        tests/darwin_native_packet_device_test.cpp
        src/platform/darwin/native_packet_device.cpp
        src/platform/darwin/native_utun.cpp
        src/platform/darwin/native_route_config.cpp
    )

    target_include_directories(darwin_native_packet_device_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    add_test(NAME darwin_native_packet_device_test COMMAND darwin_native_packet_device_test)

    add_executable(darwin_native_tls_stream_test
        tests/darwin_native_tls_stream_test.cpp
        src/platform/darwin/native_tls_stream.cpp
    )

    target_include_directories(darwin_native_tls_stream_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(darwin_native_tls_stream_test PRIVATE
        "-framework Security"
        "-framework CoreFoundation"
    )

    add_test(NAME darwin_native_tls_stream_test COMMAND darwin_native_tls_stream_test)
endif()

# ===========================================================================
# Phase 1 architecture tests
# ===========================================================================

add_executable(reconnect_policy_test
    tests/reconnect_policy_test.cpp
    src/core/tunnel_controller/reconnect_policy.cpp
)

target_include_directories(reconnect_policy_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME reconnect_policy_test COMMAND reconnect_policy_test)

add_executable(timer_scheduler_test
    tests/timer_scheduler_test.cpp
    src/core/tunnel_controller/timer_scheduler.cpp
)

target_include_directories(timer_scheduler_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(timer_scheduler_test PRIVATE
    exv-core-tunnel-timing-module
    Threads::Threads
)

set_target_properties(timer_scheduler_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME timer_scheduler_test COMMAND timer_scheduler_test)

add_executable(reconnect_deterministic_test
    tests/reconnect_deterministic_test.cpp
    src/core/tunnel_controller/reconnect_policy.cpp
)

target_include_directories(reconnect_deterministic_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME reconnect_deterministic_test COMMAND reconnect_deterministic_test)

add_executable(startup_failure_test
    tests/startup_failure_test.cpp
    src/core/tunnel_controller/native_startup_failure.cpp
)

target_include_directories(startup_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME startup_failure_test COMMAND startup_failure_test)

add_executable(core_error_mapper_test
    tests/core_error_mapper_test.cpp
    src/core/tunnel_controller/core_error_mapper.cpp
)

target_include_directories(core_error_mapper_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(core_error_mapper_test PRIVATE
    exv-core-tunnel-errors-module
)

set_target_properties(core_error_mapper_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME core_error_mapper_test COMMAND core_error_mapper_test)

add_executable(engine_event_bridge_test
    tests/engine_event_bridge_test.cpp
)

target_include_directories(engine_event_bridge_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(engine_event_bridge_test PRIVATE
    exv-core
    exv-core-tunnel-events-module
    Threads::Threads
    ${EXV_PLATFORM_LIBS}
)

set_target_properties(engine_event_bridge_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME engine_event_bridge_test COMMAND engine_event_bridge_test)

add_executable(core_session_runner_test
    tests/core_session_runner_test.cpp
)

target_include_directories(core_session_runner_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(core_session_runner_test PRIVATE exv-core Threads::Threads ${EXV_PLATFORM_LIBS})

add_test(NAME core_session_runner_test COMMAND core_session_runner_test)

add_executable(connect_intent_test
    tests/connect_intent_test.cpp
)

target_include_directories(connect_intent_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(connect_intent_test PRIVATE exv-core Threads::Threads ${EXV_PLATFORM_LIBS})

add_test(NAME connect_intent_test COMMAND connect_intent_test)

add_executable(connect_pipeline_test
    tests/connect_pipeline_test.cpp
)

target_include_directories(connect_pipeline_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(connect_pipeline_test PRIVATE exv-core Threads::Threads ${EXV_PLATFORM_LIBS})

add_test(NAME connect_pipeline_test COMMAND connect_pipeline_test)

add_executable(connect_progress_tracker_test
    tests/connect_progress_tracker_test.cpp
)

target_include_directories(connect_progress_tracker_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(connect_progress_tracker_test PRIVATE exv-core)

add_test(NAME connect_progress_tracker_test COMMAND connect_progress_tracker_test)

add_executable(connection_runtime_coordinator_test
    tests/connection_runtime_coordinator_test.cpp
)

target_include_directories(connection_runtime_coordinator_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(connection_runtime_coordinator_test PRIVATE exv-core)

add_test(NAME connection_runtime_coordinator_test
         COMMAND connection_runtime_coordinator_test)

add_executable(native_engine_config_mapper_test
    tests/native_engine_config_mapper_test.cpp
)

target_include_directories(native_engine_config_mapper_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(native_engine_config_mapper_test PRIVATE exv-core)

add_test(NAME native_engine_config_mapper_test COMMAND native_engine_config_mapper_test)

add_executable(tunnel_controller_state_machine_test
    tests/tunnel_controller_state_machine_test.cpp
    tests/support/fake_helper.cpp
    tests/support/fake_platform_network_ops.cpp
)

target_include_directories(tunnel_controller_state_machine_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

target_link_libraries(tunnel_controller_state_machine_test PRIVATE
    exv-core Threads::Threads ${EXV_PLATFORM_LIBS}
)

add_test(NAME tunnel_controller_state_machine_test COMMAND tunnel_controller_state_machine_test)

add_executable(tunnel_contract_test
    tests/tunnel_contract_test.cpp
)

target_include_directories(tunnel_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME tunnel_contract_test COMMAND tunnel_contract_test)

add_executable(tunnel_module_smoke_test
    tests/tunnel_module_smoke_test.cpp
)

target_include_directories(tunnel_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tunnel_module_smoke_test PRIVATE
    exv-core-tunnel-contract-module
)

set_target_properties(tunnel_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME tunnel_module_smoke_test COMMAND tunnel_module_smoke_test)

add_executable(tunnel_public_module_smoke_test
    tests/tunnel_public_module_smoke_test.cpp
)

target_include_directories(tunnel_public_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tunnel_public_module_smoke_test PRIVATE
    exv-core-tunnel-module
)

set_target_properties(tunnel_public_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME tunnel_public_module_smoke_test COMMAND tunnel_public_module_smoke_test)

add_executable(core_process_test
    tests/core_process_test.cpp
)

target_include_directories(core_process_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(core_process_test PRIVATE exv-core exv-helper-runtime)

add_test(NAME core_process_test COMMAND core_process_test)

add_executable(core_rpc_lane_scheduler_test
    tests/core_rpc_lane_scheduler_test.cpp
)

target_include_directories(core_rpc_lane_scheduler_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(core_rpc_lane_scheduler_test PRIVATE exv-core Threads::Threads)

add_test(NAME core_rpc_lane_scheduler_test COMMAND core_rpc_lane_scheduler_test)

add_executable(core_process_lifecycle_test
    tests/core_process_lifecycle_test.cpp
    src/cli/pipe_client.cpp
)

target_include_directories(core_process_lifecycle_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(core_process_lifecycle_test PRIVATE exv-core exv-helper-runtime Threads::Threads)

target_compile_definitions(core_process_lifecycle_test PRIVATE
    EXV_VERSION="${PROJECT_VERSION}"
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME core_process_lifecycle_test COMMAND core_process_lifecycle_test)

add_executable(core_lifecycle_registry_test
    tests/core_lifecycle_registry_test.cpp
)

target_include_directories(core_lifecycle_registry_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(core_lifecycle_registry_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(core_lifecycle_registry_test PRIVATE exv-core)

add_test(NAME core_lifecycle_registry_test COMMAND core_lifecycle_registry_test)

add_executable(core_resolver_test
    tests/core_resolver_test.cpp
)

target_include_directories(core_resolver_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(core_resolver_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(core_resolver_test PRIVATE exv-core)

add_test(NAME core_resolver_test COMMAND core_resolver_test)

add_executable(tunnel_controller_integration_test
    tests/tunnel_controller_integration_test.cpp
    tests/support/fake_helper.cpp
    tests/support/fake_platform_network_ops.cpp
    tests/support/fake_core_ui_client.cpp
    src/core/tunnel_controller/tunnel_controller_test_access.cpp
)

target_include_directories(tunnel_controller_integration_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tunnel_controller_integration_test PRIVATE
    exv-core Threads::Threads ${EXV_PLATFORM_LIBS}
)

add_test(NAME tunnel_controller_integration_test COMMAND tunnel_controller_integration_test)

add_executable(helper_lease_manager_test
    tests/helper_lease_manager_test.cpp
    src/helper/runtime/session_lease_manager.cpp
)

target_include_directories(helper_lease_manager_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME helper_lease_manager_test COMMAND helper_lease_manager_test)

add_executable(helper_cleanup_registry_test
    tests/helper_cleanup_registry_test.cpp
)

target_include_directories(helper_cleanup_registry_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(helper_cleanup_registry_test PRIVATE exv-helper-runtime)

add_test(NAME helper_cleanup_registry_test COMMAND helper_cleanup_registry_test)

add_executable(privileged_task_queue_test
    tests/privileged_task_queue_test.cpp
    src/helper/runtime/privileged_task_queue.cpp
)

target_include_directories(privileged_task_queue_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(privileged_task_queue_test PRIVATE Threads::Threads)

add_test(NAME privileged_task_queue_test COMMAND privileged_task_queue_test)

add_executable(helper_contract_test
    tests/helper_contract_test.cpp
    tests/support/fake_helper.cpp
    src/helper/common/helper_messages.cpp
    src/helper/runtime/session_lease_manager.cpp
    src/helper/runtime/cleanup_registry.cpp
    src/helper/runtime/command_validator.cpp
    src/helper/runtime/helper_lifecycle_policy.cpp
    src/helper/runtime/helper_request_dispatcher.cpp
    src/helper/runtime/privileged_task_queue.cpp
    src/helper/helper_handler.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

target_include_directories(helper_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

target_compile_definitions(helper_contract_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(helper_contract_test PRIVATE exv-helper-runtime Threads::Threads)

add_test(NAME helper_contract_test COMMAND helper_contract_test)

add_executable(helper_module_smoke_test
    tests/helper_module_smoke_test.cpp
)

target_include_directories(helper_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(helper_module_smoke_test PRIVATE
    exv-helper-protocol-module
)
set_target_properties(helper_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME helper_module_smoke_test COMMAND helper_module_smoke_test)

add_executable(config_module_smoke_test
    tests/config_module_smoke_test.cpp
)

target_include_directories(config_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(config_module_smoke_test PRIVATE
    exv-config-contract-module
)

set_target_properties(config_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME config_module_smoke_test COMMAND config_module_smoke_test)

add_executable(base_module_smoke_test
    tests/base_module_smoke_test.cpp
)

target_include_directories(base_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(base_module_smoke_test PRIVATE
    exv-base-types-module
    exv-base-errors-module
)

set_target_properties(base_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME base_module_smoke_test COMMAND base_module_smoke_test)

add_executable(log_queue_test
    tests/log_queue_test.cpp
    src/observability/log_queue.cpp
)

target_include_directories(log_queue_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(log_queue_test PRIVATE Threads::Threads)

add_test(NAME log_queue_test COMMAND log_queue_test)

add_executable(log_service_test
    tests/log_service_test.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

target_include_directories(log_service_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(log_service_test PRIVATE Threads::Threads)

add_test(NAME log_service_test COMMAND log_service_test)

add_executable(platform_log_sink_test
    tests/platform_log_sink_test.cpp
    src/platform/common/logging/file_log_sink.cpp
    src/platform/common/logging/stdout_log_sink.cpp
)

target_include_directories(platform_log_sink_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME platform_log_sink_test COMMAND platform_log_sink_test)

add_executable(observability_module_smoke_test
    tests/observability_module_smoke_test.cpp
)

target_include_directories(observability_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(observability_module_smoke_test PRIVATE
    exv-observability-log-module
)

set_target_properties(observability_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME observability_module_smoke_test COMMAND observability_module_smoke_test)

add_executable(utils_strings_test
    tests/utils_strings_test.cpp
)

target_include_directories(utils_strings_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(utils_strings_test PRIVATE
    exv-utils-strings
)

add_test(NAME utils_strings_test COMMAND utils_strings_test)

add_executable(utils_strings_module_smoke_test
    tests/utils_strings_module_smoke_test.cpp
)

target_include_directories(utils_strings_module_smoke_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(utils_strings_module_smoke_test PRIVATE
    exv-utils-strings-module
)

set_target_properties(utils_strings_module_smoke_test PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_test(NAME utils_strings_module_smoke_test COMMAND utils_strings_module_smoke_test)

add_executable(helper_network_ops_adapter_test
    tests/helper_network_ops_adapter_test.cpp
    src/helper/helper_network_ops.cpp
    src/platform/common/platform_network_ops.cpp
)

target_include_directories(helper_network_ops_adapter_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME helper_network_ops_adapter_test COMMAND helper_network_ops_adapter_test)

add_executable(app_api_rpc_dispatcher_test
    tests/app_api_rpc_dispatcher_test.cpp
    src/core/rpc/app_rpc_dispatcher.cpp
    src/core/rpc/rpc_action_metadata.cpp
    src/core/rpc/desktop_rpc_adapter.cpp
)

target_include_directories(app_api_rpc_dispatcher_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME app_api_rpc_dispatcher_test COMMAND app_api_rpc_dispatcher_test)

add_executable(app_api_status_contract_test
    tests/app_api_status_contract_test.cpp
)

target_include_directories(app_api_status_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(app_api_status_contract_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME app_api_status_contract_test COMMAND app_api_status_contract_test)

# Auth-interaction coordinator unit test — exercises the prepared-handshake
# group_select / challenge round-trip path published by run_desktop_connect_job.
# See docs/AGGREGATE_AUTH_EMPTY_RESPONSE_FIX_PLAN.md §6.
add_executable(auth_interaction_coordinator_test
    tests/auth_interaction_coordinator_test.cpp
    src/core/app_api/auth_interaction_coordinator.cpp
)

target_include_directories(auth_interaction_coordinator_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(auth_interaction_coordinator_test PRIVATE
    Threads::Threads
)

set_target_properties(auth_interaction_coordinator_test PROPERTIES
    LABELS "release-blocking;core"
)

add_test(NAME auth_interaction_coordinator_test
         COMMAND auth_interaction_coordinator_test)

add_executable(desktop_status_presenter_test
    tests/desktop_status_presenter_test.cpp
)

target_include_directories(desktop_status_presenter_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

if(MINGW)
    target_link_libraries(desktop_status_presenter_test PRIVATE
        "-Wl,--start-group"
        exv-helper-runtime
        exv-core
        "-Wl,--end-group"
    )
else()
    target_link_libraries(desktop_status_presenter_test PRIVATE
        exv-helper-runtime
        exv-core
    )
endif()

add_test(NAME desktop_status_presenter_test COMMAND desktop_status_presenter_test)

# --- Phase 4-6: core_api action tests ---

add_executable(vpn_actions_test
    tests/core_api/vpn_actions_test.cpp
    tests/support/fake_helper.cpp
    tests/support/fake_platform_network_ops.cpp
)

target_include_directories(vpn_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

target_compile_definitions(vpn_actions_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(vpn_actions_test PRIVATE exv-core exv-helper-runtime)

add_test(NAME vpn_actions_test COMMAND vpn_actions_test)

add_executable(config_actions_test
    tests/core_api/config_actions_test.cpp
)

target_include_directories(config_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(config_actions_test PRIVATE exv-core)

add_test(NAME config_actions_test COMMAND config_actions_test)

add_executable(config_initialization_test
    tests/config_initialization_test.cpp
)
add_dependencies(config_initialization_test exv-generate-distribution-config)

target_include_directories(config_initialization_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(config_initialization_test PRIVATE exv-core)

add_test(NAME config_initialization_test COMMAND config_initialization_test)

add_executable(log_actions_test
    tests/core_api/log_actions_test.cpp
)

target_include_directories(log_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(log_actions_test PRIVATE exv-core)

add_test(NAME log_actions_test COMMAND log_actions_test)

add_executable(core_hello_actions_test
    tests/core_api/core_hello_actions_test.cpp
)

target_include_directories(core_hello_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(core_hello_actions_test PRIVATE exv-core exv-helper-runtime)

add_test(NAME core_hello_actions_test COMMAND core_hello_actions_test)

add_executable(service_actions_test
    tests/core_api/service_actions_test.cpp
    tests/support/fake_helper.cpp
    tests/support/fake_platform_network_ops.cpp
)

target_include_directories(service_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(service_actions_test PRIVATE exv-core exv-helper-runtime)

add_test(NAME service_actions_test COMMAND service_actions_test)

# SystemStatusUseCases service install/uninstall/repair: validates that after
# task A3b these methods route through launch_elevated_service_op (runas) rather
# than the helper daemon. Drives the runas seam to assert error mapping and
# subcommand dispatch; the not-installed success path exercises the real
# current_service_status() poll. Target name deliberately avoids "install" so
# Windows installer-detection (UAC) does not flag the test binary.
add_executable(system_status_service_ops_test
    tests/system_status_service_ops_test.cpp
)

target_include_directories(system_status_service_ops_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(system_status_service_ops_test PRIVATE exv-core exv-helper-runtime)

add_test(NAME system_status_service_ops_test COMMAND system_status_service_ops_test)

add_executable(route_actions_test
    tests/core_api/route_actions_test.cpp
)

target_include_directories(route_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(route_actions_test PRIVATE exv-core)

add_test(NAME route_actions_test COMMAND route_actions_test)

add_executable(maintenance_actions_test
    tests/core_api/maintenance_actions_test.cpp
)

target_include_directories(maintenance_actions_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(maintenance_actions_test PRIVATE exv-core)

add_test(NAME maintenance_actions_test COMMAND maintenance_actions_test)

add_executable(error_contract_test
    tests/core_api/error_contract_test.cpp
    src/feedback/error_contract.cpp
)

target_include_directories(error_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME error_contract_test COMMAND error_contract_test)

add_executable(contract_manifest_test
    tests/contract_manifest_test.cpp
)

target_include_directories(contract_manifest_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(contract_manifest_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME contract_manifest_test COMMAND contract_manifest_test)

add_executable(cli_commands_test
    tests/cli_commands_test.cpp
    src/cli/cli_commands.cpp
    src/cli/core_request_formatter.cpp
)

target_include_directories(cli_commands_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(cli_commands_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME cli_commands_test COMMAND cli_commands_test)

add_executable(core_architecture_contract_test
    tests/core_architecture_contract_test.cpp
)

target_include_directories(core_architecture_contract_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(core_architecture_contract_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME core_architecture_contract_test COMMAND core_architecture_contract_test)

add_executable(base_observability_architecture_test
    tests/base_observability_architecture_test.cpp
)

target_include_directories(base_observability_architecture_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(base_observability_architecture_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

add_test(NAME base_observability_architecture_test COMMAND base_observability_architecture_test)

add_test(
    NAME contract_generation_check
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/generate_contracts.py --check
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_executable(native_core_connect_flow_test
    tests/integration/native_core_connect_flow_test.cpp
    tests/support/fake_helper.cpp
    tests/support/fake_platform_network_ops.cpp
)

target_include_directories(native_core_connect_flow_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME native_core_connect_flow_test COMMAND native_core_connect_flow_test)

add_executable(helper_timeout_cleanup_test
    tests/integration/helper_timeout_cleanup_test.cpp
    src/helper/runtime/session_lease_manager.cpp
    src/helper/runtime/helper_lifecycle_policy.cpp
)

target_include_directories(helper_timeout_cleanup_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME helper_timeout_cleanup_test COMMAND helper_timeout_cleanup_test)

add_executable(no_secret_in_argv_test
    tests/security/no_secret_in_argv_test.cpp
    src/cli/core_request_formatter.cpp
)

target_include_directories(no_secret_in_argv_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME no_secret_in_argv_test COMMAND no_secret_in_argv_test)

add_executable(no_secret_in_logs_test
    tests/security/no_secret_in_logs_test.cpp
    src/core/tunnel_controller/core_error_mapper.cpp
)


target_include_directories(no_secret_in_logs_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME no_secret_in_logs_test COMMAND no_secret_in_logs_test)

add_executable(credential_store_model_test
    tests/credential_store_model_test.cpp
    src/platform/common/credential_store.cpp
)

if(WIN32)
    target_sources(credential_store_model_test PRIVATE src/platform/win32/win_credential_store.cpp)
    target_link_libraries(credential_store_model_test PRIVATE advapi32)
elseif(APPLE)
    target_sources(credential_store_model_test PRIVATE src/platform/darwin/darwin_keychain_store.cpp)
    target_link_libraries(credential_store_model_test PRIVATE "-framework Security" "-framework CoreFoundation")
endif()

target_include_directories(credential_store_model_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME credential_store_model_test COMMAND credential_store_model_test)

add_executable(helper_messages_connector_test
    tests/helper_messages_connector_test.cpp
    src/helper/common/helper_messages.cpp
    src/helper/common/helper_connector.cpp
    src/helper/common/pipe_helper_client.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

target_include_directories(helper_messages_connector_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(helper_messages_connector_test PRIVATE Threads::Threads)

add_test(NAME helper_messages_connector_test COMMAND helper_messages_connector_test)

# IPC transport test: PipeHelperClient <-> raw platform server (no daemon deps)
add_executable(pipe_helper_client_test
    tests/pipe_helper_client_test.cpp
    src/helper/common/helper_messages.cpp
    src/helper/common/helper_connector.cpp
    src/helper/common/pipe_helper_client.cpp
    ${EXV_OBSERVABILITY_SOURCES}
)

target_include_directories(pipe_helper_client_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
target_link_libraries(pipe_helper_client_test PRIVATE Threads::Threads)

add_test(NAME pipe_helper_client_test COMMAND pipe_helper_client_test)

add_executable(darwin_platform_network_ops_test
    tests/darwin_platform_network_ops_test.cpp
    src/platform/darwin/platform_network_ops_darwin.cpp
    src/platform/darwin/native_utun.cpp
    src/platform/darwin/native_route_config.cpp
    src/platform/common/process_utils.cpp
)

target_include_directories(darwin_platform_network_ops_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME darwin_platform_network_ops_test COMMAND darwin_platform_network_ops_test)

if(WIN32)
    add_executable(win32_helper_oneshot_test
        tests/win32_helper_oneshot_test.cpp
    )

    target_include_directories(win32_helper_oneshot_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(win32_helper_oneshot_test PRIVATE exv-helper-runtime)

    add_test(NAME win32_helper_oneshot_test COMMAND win32_helper_oneshot_test)

    add_executable(win32_platform_network_ops_test
        tests/win32_platform_network_ops_test.cpp
        src/platform/win32/platform_network_ops_win32.cpp
        src/platform/win32/native_wintun.cpp
        src/platform/win32/native_ip_config.cpp
    )

    target_include_directories(win32_platform_network_ops_test PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(win32_platform_network_ops_test PRIVATE iphlpapi ws2_32)

    add_test(NAME win32_platform_network_ops_test COMMAND win32_platform_network_ops_test)
endif()

# ===========================================================================
# Additional test targets (Phase 4-7: protocol, auth, integration)
# ===========================================================================

add_executable(native_authenticator_test
    tests/native_authenticator_test.cpp
    src/vpn_engine/protocol/native_authenticator.cpp
    src/vpn_engine/protocol/auth.cpp
    src/vpn_engine/protocol/http.cpp
    src/vpn_engine/session_state.cpp
)

target_include_directories(native_authenticator_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_authenticator_test COMMAND native_authenticator_test)

add_executable(native_auth_session_json_test
    tests/native_auth_session_json_test.cpp
    src/vpn_engine/protocol/native_auth_session_json.cpp
)

target_include_directories(native_auth_session_json_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

add_test(NAME native_auth_session_json_test COMMAND native_auth_session_json_test)

add_executable(connection_attempt_test
    tests/connection_attempt_test.cpp
)

target_include_directories(connection_attempt_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(connection_attempt_test PRIVATE
    EXV_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
)

target_link_libraries(connection_attempt_test PRIVATE
    exv-core
    exv-helper-runtime
    Threads::Threads
)

add_test(NAME connection_attempt_test COMMAND connection_attempt_test)

add_executable(tunnel_resource_lease_test
    tests/tunnel_resource_lease_test.cpp
)

target_include_directories(tunnel_resource_lease_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(tunnel_resource_lease_test PRIVATE
    exv-core
    Threads::Threads
)

add_test(NAME tunnel_resource_lease_test COMMAND tunnel_resource_lease_test)

# NOTE: app_api_logs_test depends on the full app_api build chain (WebUI assets,
# SSE broadcaster, etc.) and is tested as part of the exv integration build.

add_executable(auth_failure_test
    tests/integration/auth_failure_test.cpp
    src/core/tunnel_controller/reconnect_policy.cpp
    tests/support/fake_helper.cpp
)

target_include_directories(auth_failure_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME auth_failure_test COMMAND auth_failure_test)

add_executable(helper_lost_test
    tests/integration/helper_lost_test.cpp
    src/core/tunnel_controller/reconnect_policy.cpp
    tests/support/fake_helper.cpp
    tests/support/fake_platform_network_ops.cpp
)

target_include_directories(helper_lost_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME helper_lost_test COMMAND helper_lost_test)

add_executable(helper_delegating_network_ops_test
    tests/helper_delegating_network_ops_test.cpp
    tests/support/fake_helper.cpp
    src/helper/common/helper_messages.cpp
    src/platform/common/helper_delegating_network_ops.cpp
    src/platform/common/platform_network_ops.cpp
)

target_include_directories(helper_delegating_network_ops_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

add_test(NAME helper_delegating_network_ops_test COMMAND helper_delegating_network_ops_test)

# ===========================================================================
# Test labels for selective test runs
# ===========================================================================
#
# Label taxonomy (CI release gate):
#   release-blocking  -- core logic, must pass for PR merge
#   env-sensitive     -- platform/DLL-dependent, informational in CI
#   integration       -- cross-module, may need helper/network
#   elevated-manual   -- requires admin/root, skipped in CI
#   legacy            -- pre-existing tests with known issues
#
# Functional labels (for local dev filtering):
#   architecture, security, core, helper, platform, ui-contract
#
# NOTE: We use set_property(TEST ... APPEND PROPERTY LABELS ...) so that a
# test can carry multiple labels (e.g. both "release-blocking" and "core").
# Plain set_tests_properties(... LABELS ...) would overwrite prior labels.
# ===========================================================================

# --- Release-blocking: core logic tests (must pass in CI) ---
set(_release_blocking_tests
    platform_status_models_test
    platform_network_ops_model_test
    feedback_test
    runtime_status_native_test
    backend_resolver_test
    native_session_state_test
    native_helper_session_test
    native_engine_contract_test
    native_event_sink_test
    proxy_tun_detector_test
    app_api_runtime_policy_test
    native_packaging_policy_test
    repository_hygiene_test
    ui_shell_contract_test
    ui_shell_core_rpc_client_test
    ui_shell_runtime_test
    ui_shell_async_host_bridge_test
    ui_shell_cmake_policy_test
    crypto_roundtrip_test
    native_url_test
    native_cstp_frame_test
    native_tls_stream_contract_test
    native_auth_parser_test
    native_protocol_session_test
    native_production_transport_test
    native_authenticator_test
    native_auth_session_json_test
    reconnect_policy_test
    timer_scheduler_test
    reconnect_deterministic_test
    startup_failure_test
    core_error_mapper_test
    engine_event_bridge_test
    core_session_runner_test
    connect_progress_tracker_test
    tunnel_controller_state_machine_test
    tunnel_contract_test
    tunnel_module_smoke_test
    tunnel_public_module_smoke_test
    helper_lease_manager_test
    core_lifecycle_registry_test
    core_resolver_test
    pipe_ipc_test
    helper_cleanup_registry_test
    native_helper_session_test
    helper_contract_test
    helper_module_smoke_test
    config_module_smoke_test
    utils_strings_test
    utils_strings_module_smoke_test
    helper_network_ops_adapter_test
    darwin_platform_network_ops_test
    no_secret_in_argv_test
    no_secret_in_logs_test
    credential_store_model_test
    app_api_rpc_dispatcher_test
    vpn_actions_test
    config_actions_test
    config_initialization_test
    log_actions_test
    core_hello_actions_test
    service_actions_test
    system_status_service_ops_test
    route_actions_test
    maintenance_actions_test
    error_contract_test
    contract_manifest_test
    core_architecture_contract_test
    cli_commands_test
    contract_generation_check
    helper_messages_connector_test
    core_process_test
    core_process_lifecycle_test
    connection_attempt_test
    helper_delegating_network_ops_test
    app_api_status_contract_test
    auth_interaction_coordinator_test
    desktop_status_presenter_test
    tunnel_controller_integration_test
)
if(WIN32)
    list(APPEND _release_blocking_tests
        win32_webview2_runtime_test
        win32_driver_status_test
        win32_platform_network_ops_test
    )
endif()
if(APPLE)
    list(APPEND _release_blocking_tests
        darwin_wkwebview_runtime_test
    )
endif()
if(UNIX AND NOT APPLE)
    list(APPEND _release_blocking_tests
        linux_webkitgtk_runtime_test
    )
endif()
set_property(TEST ${_release_blocking_tests} APPEND PROPERTY LABELS "release-blocking")

# Global MinGW DLL fix: ensure all release-blocking tests can find MinGW
# runtime DLLs.  On CI runners the toolchain bin dir is usually already on
# PATH, but local developer machines may not have it.  We inject both the
# MinGW compiler bin directory and the exv-core build directory (which
# contains the MinGW DLLs next to the test binaries) via the
# ENVIRONMENT_MODIFICATION test property.
if(WIN32 AND NOT MSVC)
    get_filename_component(MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    # All test executables link against the MinGW runtime DLLs (libgcc_s_seh,
    # libstdc++, libwinpthread) which live in MINGW_BIN_DIR. Without that dir on
    # PATH the loader fails with 0xc0000139 (entrypoint/DLL not found). Apply
    # the PATH environment to every defined test, not just the release-blocking
    # subset, so newly added tests are runnable without per-test opt-in.
    set(_exv_test_path_modifications
        "PATH=path_list_prepend:${MINGW_BIN_DIR}"
        "PATH=path_list_prepend:$<TARGET_FILE_DIR:exv-core>"
    )
    if(EXV_ENABLE_DTLS_BACKEND AND OPENSSL_ROOT_DIR)
        list(APPEND _exv_test_path_modifications
            "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin"
        )
    endif()
    get_directory_property(_all_tests TESTS)
    foreach(_test IN LISTS _all_tests)
        set_tests_properties(${_test} PROPERTIES
            ENVIRONMENT_MODIFICATION "${_exv_test_path_modifications}"
        )
    endforeach()
endif()

# --- Env-sensitive: platform/DLL-dependent tests (informational in CI) ---
# These tests depend on platform-specific DLLs (WinTun, SChannel, etc.) or
# MinGW runtime DLLs that may not be available in all CI environments.
# On Windows+MinGW they may fail with 0xc0000139 (DLL not found).
set_property(TEST
    native_fake_anyconnect_server_test
    APPEND PROPERTY LABELS "env-sensitive"
)

if(WIN32)
    set_property(TEST
        win32_native_wintun_test
        win32_native_ip_config_test
        win32_native_packet_device_test
        win32_native_tls_stream_test
        APPEND PROPERTY LABELS "env-sensitive"
    )
endif()

if(APPLE)
    set_property(TEST
        darwin_native_utun_test
        darwin_native_route_config_test
        darwin_native_packet_device_test
        darwin_native_tls_stream_test
        APPEND PROPERTY LABELS "env-sensitive"
    )
endif()

# --- Integration tests ---
set_property(TEST
    tunnel_controller_integration_test
    native_core_connect_flow_test
    helper_timeout_cleanup_test
    auth_failure_test
    helper_lost_test
    APPEND PROPERTY LABELS "integration"
)

# --- Functional labels (for local dev filtering) ---

# All Phase 1+ architecture tests
set_property(TEST
    reconnect_policy_test
    timer_scheduler_test
    core_error_mapper_test
    engine_event_bridge_test
    core_session_runner_test
    connect_progress_tracker_test
    tunnel_controller_state_machine_test
    tunnel_controller_integration_test
    tunnel_contract_test
    tunnel_public_module_smoke_test
    helper_lease_manager_test
    core_lifecycle_registry_test
    core_resolver_test
    helper_cleanup_registry_test
    native_helper_session_test
    helper_contract_test
    helper_module_smoke_test
    config_module_smoke_test
    utils_strings_test
    utils_strings_module_smoke_test
    helper_network_ops_adapter_test
    darwin_platform_network_ops_test
    app_api_rpc_dispatcher_test
    native_core_connect_flow_test
    helper_timeout_cleanup_test
    no_secret_in_argv_test
    no_secret_in_logs_test
    credential_store_model_test
    helper_messages_connector_test
    platform_network_ops_model_test
    vpn_actions_test
    config_actions_test
    config_initialization_test
    log_actions_test
    core_hello_actions_test
    service_actions_test
    system_status_service_ops_test
    route_actions_test
    maintenance_actions_test
    error_contract_test
    contract_manifest_test
    core_architecture_contract_test
    cli_commands_test
    contract_generation_check
    auth_failure_test
    helper_lost_test
    native_authenticator_test
    native_auth_session_json_test
    core_process_test
    core_process_lifecycle_test
    helper_delegating_network_ops_test
    app_api_status_contract_test
    desktop_status_presenter_test
    APPEND PROPERTY LABELS "architecture"
)

# Security-focused tests
set_property(TEST
    no_secret_in_argv_test
    no_secret_in_logs_test
    credential_store_model_test
    APPEND PROPERTY LABELS "security"
)

# Core module tests
set_property(TEST
    reconnect_policy_test
    timer_scheduler_test
    core_error_mapper_test
    core_session_runner_test
    connect_progress_tracker_test
    tunnel_controller_state_machine_test
    tunnel_controller_integration_test
    core_process_test
    core_process_lifecycle_test
    core_lifecycle_registry_test
    core_resolver_test
    core_hello_actions_test
    log_actions_test
    tunnel_contract_test
    tunnel_module_smoke_test
    tunnel_public_module_smoke_test
    APPEND PROPERTY LABELS "core"
)

# Helper subsystem tests
set_property(TEST
    helper_lease_manager_test
    helper_cleanup_registry_test
    native_helper_session_test
    helper_contract_test
    helper_module_smoke_test
    helper_network_ops_adapter_test
    helper_messages_connector_test
    helper_timeout_cleanup_test
    APPEND PROPERTY LABELS "helper"
)

# Platform abstraction tests
set_property(TEST
    platform_network_ops_model_test
    credential_store_model_test
    helper_network_ops_adapter_test
    darwin_platform_network_ops_test
    helper_delegating_network_ops_test
    APPEND PROPERTY LABELS "platform"
)
if(WIN32)
    set_property(TEST
        win32_platform_network_ops_test
        APPEND PROPERTY LABELS "platform" "architecture"
    )
endif()

# UI / RPC contract tests
set_property(TEST
    app_api_rpc_dispatcher_test
    vpn_actions_test
    config_actions_test
    log_actions_test
    core_hello_actions_test
    core_lifecycle_registry_test
    core_resolver_test
    tunnel_contract_test
    config_module_smoke_test
    service_actions_test
    system_status_service_ops_test
    route_actions_test
    maintenance_actions_test
    error_contract_test
    contract_manifest_test
    core_architecture_contract_test
    cli_commands_test
    contract_generation_check
    tunnel_module_smoke_test
    tunnel_public_module_smoke_test
    utils_strings_test
    utils_strings_module_smoke_test
    core_process_test
    core_process_lifecycle_test
    app_api_status_contract_test
    desktop_status_presenter_test
    APPEND PROPERTY LABELS "ui-contract"
)

# Install target
if(WIN32)
  install(TARGETS exv exv-cli exv-helper DESTINATION "C:/Program Files/EXV")
else()
  install(TARGETS exv exv-cli exv-helper DESTINATION /usr/local/bin)
endif()
