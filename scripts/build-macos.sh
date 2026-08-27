#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_ROOT="$REPO_ROOT/build/macos"
ACTION="${1:-all}"

export EXV_BUILD_PLATFORM=macos
export EXV_WEBUI_DIST_DIR="$BUILD_ROOT/webview/dist"

usage() {
  cat <<EOF
Usage: $(basename "$0") [cpp|test|webview|desktop|all|policy|clean]

  cpp      Configure and build the native macOS targets into build/macos/cpp
  test     Run the focused native regression tests from build/macos/cpp
  webview  Build native targets, run tests, then package the native WebView shell
  desktop  Build native targets, run tests, then package the native WebView shell
  all      Build native targets, run tests, then package the native WebView shell
  policy   Run the cross-platform native packaging policy test only
  clean    Remove build/macos

Requires Homebrew LLVM (not Apple Clang) for C++20 modules.
EOF
}

setup_llvm() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "missing required tool: brew" >&2
    echo "Install Homebrew, then: brew install llvm ninja" >&2
    exit 70
  fi

  local llvm_prefix
  if ! llvm_prefix="$(brew --prefix llvm 2>/dev/null)"; then
    echo "missing required LLVM toolchain: brew install llvm" >&2
    exit 70
  fi

  if [[ ! -x "$llvm_prefix/bin/clang" ||
        ! -x "$llvm_prefix/bin/clang++" ||
        ! -x "$llvm_prefix/bin/clang-scan-deps" ]]; then
    echo "Homebrew LLVM is incomplete under $llvm_prefix: brew reinstall llvm" >&2
    exit 70
  fi

  if ! command -v ninja >/dev/null 2>&1; then
    echo "missing required tool: ninja" >&2
    echo "Install with: brew install ninja" >&2
    exit 70
  fi

  export PATH="$llvm_prefix/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
  export CC="$llvm_prefix/bin/clang"
  export CXX="$llvm_prefix/bin/clang++"

  case "$("$CXX" --version | head -1)" in
    *Apple*)
      echo "refusing Apple clang; install Homebrew llvm and retry" >&2
      exit 70
      ;;
  esac

  CMAKE_LLVM_ARGS=(
    -DCMAKE_CXX_COMPILER="$llvm_prefix/bin/clang++"
    -DCMAKE_CXX_COMPILER_CLANG_SCAN_DEPS="$llvm_prefix/bin/clang-scan-deps"
  )
}

build_cpp() {
  local ui_shell="${1:-off}"
  setup_llvm
  (
    cd "$REPO_ROOT"
    if [[ "$ui_shell" == "on" ]]; then
      cmake --preset macos-release "${CMAKE_LLVM_ARGS[@]}" -DEXV_BUILD_UI_SHELL=ON
    else
      cmake --preset macos-release "${CMAKE_LLVM_ARGS[@]}"
    fi
    cmake --build --preset macos-release --target exv exv-helper exv-ui platform_status_models_test backend_resolver_test ui_shell_contract_test ui_shell_core_rpc_client_test ui_shell_cmake_policy_test darwin_wkwebview_runtime_test
  )
}

run_tests() {
  setup_llvm
  (
    cd "$REPO_ROOT"
    ctest --preset macos-release -R 'platform_status_models_test|backend_resolver_test|ui_shell_contract_test|ui_shell_core_rpc_client_test|ui_shell_cmake_policy_test|darwin_wkwebview_runtime_test'
  )
}

run_webui_renderer() {
  (
    cd "$REPO_ROOT/webui"
    pnpm run webview:compile
  )
}

package_webview() {
  (
    cd "$REPO_ROOT"
    python3 scripts/package_ui_shell.py --platform macos
    test -d "$BUILD_ROOT/webview/package/EXV/EXV.app"
  )
}

run_policy_tests() {
  setup_llvm
  (
    cd "$REPO_ROOT"
    cmake --build --preset macos-release --target native_packaging_policy_test
    ctest --preset macos-release -R 'native_packaging_policy_test'
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
  policy)
    run_policy_tests
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
