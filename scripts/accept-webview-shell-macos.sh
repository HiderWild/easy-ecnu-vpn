#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$REPO_ROOT/build/webview-acceptance/macos"
mkdir -p "$LOG_DIR"

require_tool() {
  local tool="$1"
  local install_hint="$2"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    echo "$install_hint" >&2
    exit 70
  fi
}

require_tool ninja "Install Ninja before running macOS acceptance, for example: brew install ninja"
require_tool brew "Install Homebrew before running macOS acceptance, then run: brew install llvm"
require_tool pnpm "Install pnpm before running macOS acceptance, for example: corepack enable pnpm"

if ! LLVM_PREFIX="$(brew --prefix llvm 2>/dev/null)"; then
  echo "missing required LLVM toolchain: brew install llvm" >&2
  exit 70
fi

if [[ ! -x "$LLVM_PREFIX/bin/clang" ||
      ! -x "$LLVM_PREFIX/bin/clang++" ||
      ! -x "$LLVM_PREFIX/bin/clang-scan-deps" ]]; then
  echo "Homebrew LLVM is missing clang, clang++, or clang-scan-deps: brew reinstall llvm" >&2
  exit 70
fi

export PATH="$LLVM_PREFIX/bin:$PATH"
export CC="$LLVM_PREFIX/bin/clang"
export CXX="$LLVM_PREFIX/bin/clang++"

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

run_logged contracts.log python3 scripts/generate_contracts.py --check
run_logged configure.log cmake --fresh --preset macos-release \
  -DCMAKE_CXX_COMPILER="$LLVM_PREFIX/bin/clang++" \
  -DEXV_BUILD_UI_SHELL=ON
run_logged build.log cmake --build build/macos/cpp --config Release
run_logged ctest.log ctest --test-dir build/macos/cpp -C Release --output-on-failure
run_logged webui-install.log pnpm --dir webui install --frozen-lockfile
run_logged package.log bash scripts/build-macos.sh desktop
run_logged smoke.log bash scripts/macos-packaging-smoke.sh
run_logged diff-check.log git diff --check
