#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_ROOT="$REPO_ROOT/build/linux"
ACTION="${1:-all}"

export EXV_BUILD_PLATFORM=linux
export EXV_WEBUI_DIST_DIR="$BUILD_ROOT/webview/dist"
export CI="${CI:-true}"

detect_clang_scan_deps() {
  if command -v clang-scan-deps >/dev/null 2>&1; then
    command -v clang-scan-deps
    return 0
  fi
  local candidate
  for candidate in clang-scan-deps-20 clang-scan-deps-19 clang-scan-deps-18 clang-scan-deps-17; do
    if command -v "$candidate" >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

linux_cmake_toolchain_args() {
  if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
    export CC="${CC:-$(command -v clang)}"
    export CXX="${CXX:-$(command -v clang++)}"
  fi

  if [[ "${CXX:-}" == *clang++* ]]; then
    local clang_scan_deps
    if ! clang_scan_deps="$(detect_clang_scan_deps)"; then
      echo "missing required tool: clang-scan-deps" >&2
      echo "Install clang tools before building Linux WebView shell, for example: apt-get install clang-tools-18" >&2
      exit 70
    fi
    printf '%s\n' "-DCMAKE_CXX_COMPILER=$CXX"
    printf '%s\n' "-DCMAKE_CXX_COMPILER_CLANG_SCAN_DEPS=$clang_scan_deps"
  fi
}

require_webui_toolchain() {
  if ! command -v node >/dev/null 2>&1; then
    echo "missing required tool: node" >&2
    echo "Install Node.js 20.19+ or 22.12+ before building the Linux WebView renderer." >&2
    exit 70
  fi
  if ! command -v pnpm >/dev/null 2>&1; then
    echo "missing required tool: pnpm" >&2
    echo "Install pnpm before building the Linux WebView renderer, for example: corepack enable pnpm" >&2
    exit 70
  fi
  if ! node -e "const [major, minor] = process.versions.node.split('.').map(Number); process.exit(((major === 20 && minor >= 19) || (major === 22 && minor >= 12) || major > 22) ? 0 : 1);"; then
    echo "Node.js 20.19+ or 22.12+ is required for the Linux WebView renderer build." >&2
    echo "Current Node.js: $(node --version)" >&2
    exit 70
  fi
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [cpp|test|webview|desktop|all|clean]

  cpp      Configure and build the native Linux targets into build/linux/cpp
  test     Run the focused native regression tests from build/linux/cpp
  webview  Build native targets, run tests, then package the native WebView shell
  desktop  Build native targets, run tests, then package the native WebView shell
  all      Build native targets, run tests, then package the native WebView shell
  clean    Remove build/linux
EOF
}

build_cpp() {
  local ui_shell="${1:-off}"
  (
    cd "$REPO_ROOT"
    mapfile -t cmake_toolchain_args < <(linux_cmake_toolchain_args)
    if [[ "$ui_shell" == "on" ]]; then
      cmake --preset linux-release -DEXV_BUILD_UI_SHELL=ON "${cmake_toolchain_args[@]}"
    else
      cmake --preset linux-release "${cmake_toolchain_args[@]}"
    fi
    cmake --build --preset linux-release --target exv exv-helper exv-ui platform_status_models_test backend_resolver_test native_packaging_policy_test ui_shell_contract_test ui_shell_core_rpc_client_test ui_shell_cmake_policy_test linux_webkitgtk_runtime_test
  )
}

run_tests() {
  (
    cd "$REPO_ROOT"
    ctest --preset linux-release -R 'platform_status_models_test|backend_resolver_test|native_packaging_policy_test|ui_shell_contract_test|ui_shell_core_rpc_client_test|ui_shell_cmake_policy_test|linux_webkitgtk_runtime_test'
  )
}

run_webui_renderer() {
  (
    require_webui_toolchain
    cd "$REPO_ROOT/webui"
    pnpm run webview:compile
  )
}

package_webview() {
  (
    cd "$REPO_ROOT"
    python3 scripts/package_ui_shell.py
  )
}

case "$ACTION" in
  cpp)
    build_cpp
    ;;
  test)
    run_tests
    ;;
  webview)
    run_webui_renderer
    build_cpp on
    run_tests
    package_webview
    ;;
  desktop)
    run_webui_renderer
    build_cpp on
    run_tests
    package_webview
    ;;
  all)
    run_webui_renderer
    build_cpp on
    run_tests
    package_webview
    ;;
  clean)
    rm -rf "$BUILD_ROOT"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
