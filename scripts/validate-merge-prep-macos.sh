#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKIP_DESKTOP=0
DESKTOP_SMOKE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-desktop)
      SKIP_DESKTOP=1
      ;;
    --desktop-smoke)
      DESKTOP_SMOKE=1
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
  shift
done

cd "$REPO_ROOT"

echo "[merge-prep] Build frontend assets for native embedding..."
(
  cd "$REPO_ROOT/webui"
  pnpm run build
)

echo "[merge-prep] Configure and build native targets..."
cmake --preset macos-release
cmake --build --preset macos-release --target exv exv-helper exv_release_blocking_tests

echo "[merge-prep] Run release-blocking native regression tests..."
ctest --preset macos-release -L release-blocking --output-on-failure

if [[ "$SKIP_DESKTOP" -eq 0 ]]; then
  echo "[merge-prep] Build native WebView desktop package..."
  bash "$SCRIPT_DIR/build-macos.sh" desktop
fi

if [[ "$DESKTOP_SMOKE" -eq 1 ]]; then
  echo "[merge-prep] Run native WebView package smoke checks..."
  bash "$SCRIPT_DIR/macos-packaging-smoke.sh"
fi

echo "[merge-prep] macOS validation complete."
