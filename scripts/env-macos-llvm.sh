#!/usr/bin/env bash
# Source this for interactive EXV Darwin builds:
#   source scripts/env-macos-llvm.sh
#
# Puts Homebrew LLVM ahead of Apple Clang and exports CC/CXX for CMake.

set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
  echo "brew not found; install Homebrew first" >&2
  return 1 2>/dev/null || exit 1
fi

llvm_prefix="$(brew --prefix llvm 2>/dev/null || true)"
if [[ -z "${llvm_prefix}" || ! -x "${llvm_prefix}/bin/clang++" ]]; then
  echo "Homebrew llvm not found. Install with: brew install llvm ninja" >&2
  return 1 2>/dev/null || exit 1
fi

export PATH="${llvm_prefix}/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"
export CC="${llvm_prefix}/bin/clang"
export CXX="${llvm_prefix}/bin/clang++"
export CMAKE_PREFIX_PATH="${llvm_prefix}${CMAKE_PREFIX_PATH:+:${CMAKE_PREFIX_PATH}}"

case "$("${CXX}" --version | head -1)" in
  *Apple*)
    echo "refusing Apple clang; install Homebrew llvm and retry" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

echo "EXV macOS toolchain ready: $("${CXX}" --version | head -1)"
echo "  CC=${CC}"
echo "  CXX=${CXX}"
echo "  ninja=$(command -v ninja 2>/dev/null || echo missing)"
