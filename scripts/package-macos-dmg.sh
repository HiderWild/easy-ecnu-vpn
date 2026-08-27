#!/usr/bin/env bash
# One-click macOS desktop build + drag-to-Applications DMG packaging.
#
# Produces:
#   build/macos/webview/package/EXV/EXV.app
#   build/macos/release/EXV-<version>-macos-<arch>.dmg
#
# Requirements:
#   - Homebrew LLVM (not Apple Clang) for C++20
#   - cmake, ninja, pnpm, python3, hdiutil, sips, osascript, swift

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_ROOT="$REPO_ROOT/build/macos"
PACKAGE_ROOT="$BUILD_ROOT/webview/package/EXV"
APP_BUNDLE="$PACKAGE_ROOT/EXV.app"
RELEASE_DIR="$BUILD_ROOT/release"
ICON_PNG="$REPO_ROOT/assets/icons/icons/1024x1024.png"
ICON_FALLBACK="$REPO_ROOT/assets/icons/icon.png"
BG_SWIFT="$SCRIPT_DIR/generate-macos-dmg-background.swift"
DSSTORE_PY="$SCRIPT_DIR/write-macos-dmg-dsstore.py"

SKIP_BUILD=0
DEV_BUILD=0
WINDOW_WIDTH=660
WINDOW_HEIGHT=420
ICON_SIZE=128
APP_ICON_X=160
APP_ICON_Y=190
APPS_ICON_X=500
APPS_ICON_Y=190
WATERMARK_OPACITY="0.18"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

  One-click path:
    1) configure Homebrew LLVM
    2) install webui deps if needed
    3) build + package desktop shell (EXV.app)
    4) generate DMG with Applications drop target
    5) watermark background: icon top-left quarter, semi-transparent,
       placed in the window bottom-right quarter

Options:
  --skip-build   Reuse an existing EXV.app under build/macos/webview/package/EXV
  --dev-build    Name artifact EXV-<version>-dev.<n>-macos-<arch>.dmg
  -h, --help     Show this help
EOF
}

log() {
  printf '[macos-dmg] %s\n' "$*"
}

die() {
  printf '[macos-dmg] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --dev-build)
      DEV_BUILD=1
      shift
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      usage
      die "unknown option: $1"
      ;;
  esac
done

detect_version() {
  local version
  version="$(
    python3 - <<'PY'
from pathlib import Path
import re
text = Path("CMakeLists.txt").read_text(encoding="utf-8")
match = re.search(r'project\s*\(\s*exv\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)', text, re.I)
if not match:
    raise SystemExit("project(exv VERSION ...) not found in CMakeLists.txt")
print(match.group(1))
PY
  )"
  printf '%s\n' "$version"
}

next_dev_number() {
  local version="$1"
  local arch="$2"
  python3 - "$RELEASE_DIR" "$version" "$arch" <<'PY'
import re
import sys
from pathlib import Path

release_dir = Path(sys.argv[1])
version = sys.argv[2]
arch = sys.argv[3]
pattern = re.compile(
    rf"^EXV-{re.escape(version)}-dev\.([0-9]+)-macos-{re.escape(arch)}\.dmg$"
)
highest = 0
if release_dir.is_dir():
    for path in release_dir.iterdir():
        match = pattern.match(path.name)
        if match:
            highest = max(highest, int(match.group(1)))
print(highest + 1)
PY
}

setup_llvm() {
  require_cmd brew
  local llvm_prefix
  if ! llvm_prefix="$(brew --prefix llvm 2>/dev/null)"; then
    die "Homebrew llvm not found. Install with: brew install llvm"
  fi
  [[ -x "$llvm_prefix/bin/clang" && -x "$llvm_prefix/bin/clang++" ]] \
    || die "Homebrew llvm is incomplete under $llvm_prefix"
  export PATH="$llvm_prefix/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
  export CC="$llvm_prefix/bin/clang"
  export CXX="$llvm_prefix/bin/clang++"
  log "Using LLVM: $($CXX --version | head -1)"
  case "$($CXX --version | head -1)" in
    *Apple*)
      die "refusing Apple clang; install Homebrew llvm and retry"
      ;;
  esac
}

ensure_webui_deps() {
  if [[ ! -d "$REPO_ROOT/webui/node_modules" ]]; then
    log "Installing webui dependencies"
    (cd "$REPO_ROOT/webui" && pnpm install)
  fi
}

build_desktop() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    log "Skipping build (--skip-build)"
  else
    ensure_webui_deps
    log "Building desktop package"
    (
      cd "$REPO_ROOT"
      bash scripts/build-macos.sh desktop
    )
  fi
  [[ -d "$APP_BUNDLE" ]] || die "EXV.app missing after build: $APP_BUNDLE"
  [[ -x "$APP_BUNDLE/Contents/MacOS/EXV" ]] \
    || die "bundle executable missing: $APP_BUNDLE/Contents/MacOS/EXV"
}

make_background() {
  local out_path="$1"
  local icon_path="$ICON_PNG"
  [[ -f "$icon_path" ]] || icon_path="$ICON_FALLBACK"
  [[ -f "$icon_path" ]] || die "app icon PNG not found under assets/icons"
  [[ -f "$BG_SWIFT" ]] || die "background generator missing: $BG_SWIFT"
  require_cmd swift
  log "Generating DMG background watermark"
  swift "$BG_SWIFT" \
    "$icon_path" \
    "$out_path" \
    "$WINDOW_WIDTH" \
    "$WINDOW_HEIGHT" \
    "$WATERMARK_OPACITY" >/dev/null
  [[ -f "$out_path" ]] || die "background PNG was not created: $out_path"
}

stage_dmg_root() {
  local stage_dir="$1"
  local bg_png="$2"
  rm -rf "$stage_dir"
  mkdir -p "$stage_dir/.background"
  # Copy the app bundle as a top-level item users can drag.
  ditto "$APP_BUNDLE" "$stage_dir/EXV.app"
  ln -s /Applications "$stage_dir/Applications"
  cp "$bg_png" "$stage_dir/.background/background.png"
}

write_dsstore_layout() {
  local target_dir="$1"
  [[ -f "$DSSTORE_PY" ]] || die "DS_Store writer missing: $DSSTORE_PY"
  log "Writing Finder DS_Store layout"
  python3 "$DSSTORE_PY" \
    "$target_dir" \
    --width "$WINDOW_WIDTH" \
    --height "$WINDOW_HEIGHT" \
    --icon-size "$ICON_SIZE" \
    --app-x "$APP_ICON_X" \
    --app-y "$APP_ICON_Y" \
    --applications-x "$APPS_ICON_X" \
    --applications-y "$APPS_ICON_Y" >/dev/null
  [[ -f "$target_dir/.DS_Store" ]] || die "DS_Store was not created under $target_dir"
}

try_configure_finder_layout() {
  local volume_name="$1"

  # Optional nicety when a local GUI session is available. Never fail the build
  # path if Finder automation times out over SSH/headless sessions.
  if ! command -v osascript >/dev/null 2>&1; then
    return 0
  fi

  log "Attempting Finder window polish (non-fatal if unavailable)"
  if ! osascript <<EOF
tell application "Finder"
  tell disk "$volume_name"
    open
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set bounds of container window to {100, 100, $((100 + WINDOW_WIDTH)), $((100 + WINDOW_HEIGHT))}
    set theViewOptions to the icon view options of container window
    set arrangement of theViewOptions to not arranged
    set icon size of theViewOptions to $ICON_SIZE
    try
      set background picture of theViewOptions to file ".background:background.png"
    end try
    set position of item "EXV.app" of container window to {$APP_ICON_X, $APP_ICON_Y}
    set position of item "Applications" of container window to {$APPS_ICON_X, $APPS_ICON_Y}
    update without registering applications
    delay 0.5
    close
  end tell
end tell
EOF
  then
    log "Finder polish skipped/failed; continuing with DS_Store layout"
  fi
}

create_dmg() {
  local version="$1"
  local arch
  arch="$(uname -m)"
  case "$arch" in
    arm64|aarch64) arch="arm64" ;;
    x86_64|amd64) arch="x64" ;;
  esac

  mkdir -p "$RELEASE_DIR"
  local artifact_version="$version"
  if [[ "$DEV_BUILD" -eq 1 ]]; then
    local n
    n="$(next_dev_number "$version" "$arch")"
    artifact_version="${version}-dev.${n}"
  fi

  local dmg_name="EXV-${artifact_version}-macos-${arch}.dmg"
  local dmg_path="$RELEASE_DIR/$dmg_name"
  # Avoid spaces in volume names; Finder AppleScript disk targeting is brittle.
  local volume_name="EXV-${version}"
  local work_root
  work_root="$(mktemp -d "${TMPDIR:-/tmp}/exv-macos-dmg.XXXXXX")"
  local stage_dir="$work_root/stage"
  local rw_dmg="$work_root/exv-rw.dmg"
  local bg_png="$work_root/background.png"
  # Trap callbacks can outlive locals under `set -u`; keep state in globals.
  EXV_DMG_MOUNT_POINT=""
  EXV_DMG_WORK_ROOT="$work_root"
  EXV_DMG_VOLUME_NAME="$volume_name"
  EXV_DMG_VERIFY_MOUNT=""
  EXV_DMG_VERIFY_ROOT=""

  cleanup() {
    local mp="${EXV_DMG_MOUNT_POINT:-}"
    local vol="${EXV_DMG_VOLUME_NAME:-}"
    local wr="${EXV_DMG_WORK_ROOT:-}"
    if [[ -n "$mp" && -d "$mp" ]]; then
      hdiutil detach "$mp" -force >/dev/null 2>&1 || true
    fi
    if [[ -n "$vol" && -d "/Volumes/$vol" ]]; then
      hdiutil detach "/Volumes/$vol" -force >/dev/null 2>&1 || true
    fi
    if [[ -n "$wr" && -d "$wr" ]]; then
      rm -rf "$wr"
    fi
  }
  trap cleanup EXIT

  make_background "$bg_png"
  stage_dmg_root "$stage_dir" "$bg_png"
  # Do NOT write .DS_Store on the APFS staging folder. mac_alias/Alias needs
  # HFS+/volume CNIDs; write layout only after the read-write image is mounted.

  # Size with headroom for Finder metadata / DS_Store growth.
  local stage_kb
  stage_kb="$(du -sk "$stage_dir" | awk '{print $1}')"
  local image_mb=$(( (stage_kb / 1024) + 64 ))
  if [[ "$image_mb" -lt 80 ]]; then
    image_mb=80
  fi

  log "Creating read-write DMG (${image_mb} MB)"
  hdiutil create \
    -srcfolder "$stage_dir" \
    -volname "$volume_name" \
    -fs HFS+ \
    -fsargs "-c c=64,a=16,e=16" \
    -format UDRW \
    -size "${image_mb}m" \
    -ov \
    "$rw_dmg" >/dev/null

  log "Mounting temporary image"
  local mount_output
  mount_output="$(hdiutil attach -readwrite -noverify -noautoopen "$rw_dmg")"
  EXV_DMG_MOUNT_POINT="$(
    printf '%s\n' "$mount_output" \
      | awk '($NF ~ /^\/Volumes\//){print $NF; exit}'
  )"
  [[ -n "${EXV_DMG_MOUNT_POINT:-}" && -d "$EXV_DMG_MOUNT_POINT" ]] \
    || die "failed to determine mount point from hdiutil attach output"

  # Write Finder metadata on the live HFS+ volume (CNIDs are valid here).
  write_dsstore_layout "$EXV_DMG_MOUNT_POINT"
  try_configure_finder_layout "$volume_name"

  sync
  sleep 1
  hdiutil detach "$EXV_DMG_MOUNT_POINT" >/dev/null
  EXV_DMG_MOUNT_POINT=""

  log "Compressing final DMG"
  rm -f "$dmg_path"
  hdiutil convert "$rw_dmg" -format UDZO -imagekey zlib-level=9 -o "$dmg_path" >/dev/null

  # Basic validation of the finished image.
  hdiutil verify "$dmg_path" >/dev/null

  EXV_DMG_VERIFY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/exv-macos-dmg-verify.XXXXXX")"
  cleanup_verify() {
    local vm="${EXV_DMG_VERIFY_MOUNT:-}"
    local vr="${EXV_DMG_VERIFY_ROOT:-}"
    if [[ -n "$vm" && -d "$vm" ]]; then
      hdiutil detach "$vm" -force >/dev/null 2>&1 || true
    fi
    if [[ -n "$vr" && -d "$vr" ]]; then
      rm -rf "$vr"
    fi
  }
  trap 'cleanup; cleanup_verify' EXIT

  EXV_DMG_VERIFY_MOUNT="$(
    hdiutil attach -readonly -nobrowse -noverify -mountroot "$EXV_DMG_VERIFY_ROOT" "$dmg_path" \
      | awk '($NF ~ /\//){print $NF; exit}'
  )"
  [[ -n "${EXV_DMG_VERIFY_MOUNT:-}" && -d "$EXV_DMG_VERIFY_MOUNT" ]] \
    || die "failed to mount final DMG for verification"
  [[ -d "$EXV_DMG_VERIFY_MOUNT/EXV.app" ]] || die "final DMG is missing EXV.app"
  [[ -L "$EXV_DMG_VERIFY_MOUNT/Applications" ]] || die "final DMG is missing Applications symlink"
  [[ -f "$EXV_DMG_VERIFY_MOUNT/.background/background.png" ]] \
    || die "final DMG is missing background image"
  [[ -f "$EXV_DMG_VERIFY_MOUNT/.DS_Store" ]] || die "final DMG is missing Finder layout metadata"
  hdiutil detach "$EXV_DMG_VERIFY_MOUNT" >/dev/null
  EXV_DMG_VERIFY_MOUNT=""
  cleanup_verify
  EXV_DMG_VERIFY_ROOT=""
  trap - EXIT
  cleanup

  log "DMG ready: $dmg_path"
  printf '%s\n' "$dmg_path"
}

main() {
  cd "$REPO_ROOT"
  require_cmd cmake
  require_cmd ninja
  require_cmd pnpm
  require_cmd python3
  require_cmd hdiutil
  require_cmd ditto
  require_cmd osascript
  require_cmd swift
  require_cmd awk
  require_cmd du

  setup_llvm
  local version
  version="$(detect_version)"
  log "Product version: $version"

  build_desktop
  create_dmg "$version"
}

main "$@"
