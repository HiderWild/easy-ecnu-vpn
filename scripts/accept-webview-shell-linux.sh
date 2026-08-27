#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$REPO_ROOT/build/webview-acceptance/linux"
mkdir -p "$LOG_DIR"

export CI="${CI:-true}"

require_tool() {
  local tool="$1"
  local install_hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    echo "$install_hint" >&2
    exit 70
  fi
}

require_webui_toolchain() {
  require_tool node "Install Node.js 20.19+ or 22.12+ before running Linux WebView acceptance."
  require_tool pnpm "Install pnpm before running Linux acceptance, for example: corepack enable pnpm"
  if ! node -e "const [major, minor] = process.versions.node.split('.').map(Number); process.exit(((major === 20 && minor >= 19) || (major === 22 && minor >= 12) || major > 22) ? 0 : 1);"; then
    echo "Node.js 20.19+ or 22.12+ is required for the Linux WebView renderer build." >&2
    echo "Current Node.js: $(node --version)" >&2
    exit 70
  fi
}

run_logged() {
  local log_name="$1"
  shift
  local log_path="$LOG_DIR/$log_name"
  (
    cd "$REPO_ROOT"
    "$@"
  ) 2>&1 | tee "$log_path"
  local status=${PIPESTATUS[0]}
  if [[ "$status" -ne 0 ]]; then
    echo "Command failed with exit $status. See $log_path" >&2
    exit "$status"
  fi
}

require_webui_toolchain

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

if command -v clang >/dev/null 2>&1 && command -v clang++ >/dev/null 2>&1; then
  export CC="${CC:-$(command -v clang)}"
  export CXX="${CXX:-$(command -v clang++)}"
fi

CMAKE_TOOLCHAIN_ARGS=()
if [[ "${CXX:-}" == *clang++* ]]; then
  if ! CLANG_SCAN_DEPS="$(detect_clang_scan_deps)"; then
    echo "missing required tool: clang-scan-deps" >&2
    echo "Install clang tools before running Linux acceptance, for example: apt-get install clang-tools-18" >&2
    exit 70
  fi
  CMAKE_TOOLCHAIN_ARGS+=(
    -DCMAKE_CXX_COMPILER="$CXX"
    -DCMAKE_CXX_COMPILER_CLANG_SCAN_DEPS="$CLANG_SCAN_DEPS"
  )
fi

run_logged contracts.log python3 scripts/generate_contracts.py --check
run_logged configure.log cmake --fresh --preset linux-release -DEXV_BUILD_UI_SHELL=ON "${CMAKE_TOOLCHAIN_ARGS[@]}"
run_logged build.log cmake --build build/linux/cpp --config Release
run_logged ctest.log ctest --test-dir build/linux/cpp -C Release --output-on-failure
run_logged webui-install.log pnpm --dir webui install --frozen-lockfile
run_logged package.log bash scripts/build-linux.sh desktop
run_logged diff-check.log git -c core.autocrlf=true diff --check
