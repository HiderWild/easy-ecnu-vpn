#!/usr/bin/env bash
# Install/refresh the LaunchDaemon helper from the local build tree and ensure
# com.exv.helper is bootstrapped and responding.
#
# Usage:
#   sudo ./scripts/install-macos-helper.sh
#   sudo ./scripts/install-macos-helper.sh /path/to/exv-helper
#
# Why this exists:
#   Interactive osascript install paths can report failure when any nested
#   launchctl step returns non-zero, even if the binary was already copied.
#   This script is the deterministic operator path after a local desktop build.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HELPER_SRC="${1:-$REPO_ROOT/build/macos/cpp/exv-helper}"
HELPER_DST="/Library/Application Support/EXV/Helper/exv-helper"
PLIST_DST="/Library/LaunchDaemons/com.exv.helper.plist"
SOCKET_DIR="/var/run/exv-helper"
SOCKET_PATH="$SOCKET_DIR/exv-helper.sock"
LABEL="com.exv.helper"

die() {
  printf 'install-macos-helper: ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'install-macos-helper: %s\n' "$*"
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "run with sudo"
}

write_plist() {
  local helper_q
  helper_q="$(printf '%s' "$HELPER_DST" | sed "s/'/'\\\\''/g")"
  cat >"$PLIST_DST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>mkdir -p ${SOCKET_DIR} &amp;&amp; chmod 0755 ${SOCKET_DIR} &amp;&amp; if [ ! -x '${helper_q}' ]; then exit 0; fi; exec '${helper_q}' --service</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>/var/log/exv-helper.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/exv-helper.log</string>
  <key>ThrottleInterval</key>
  <integer>10</integer>
</dict>
</plist>
EOF
  chmod 0644 "$PLIST_DST"
}

main() {
  require_root
  [[ -x "$HELPER_SRC" ]] || die "helper binary not found/executable: $HELPER_SRC"

  log "Installing helper from $HELPER_SRC"
  mkdir -p "$(dirname "$HELPER_DST")" "$SOCKET_DIR"
  chmod 0755 "$SOCKET_DIR"
  cp -f "$HELPER_SRC" "$HELPER_DST"
  chmod 0755 "$HELPER_DST"

  write_plist
  log "Wrote $PLIST_DST"

  # Tolerate "not loaded" / already-disabled edges; never abort on bootout.
  launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  launchctl bootout system "$PLIST_DST" >/dev/null 2>&1 || true
  launchctl enable "system/$LABEL" >/dev/null 2>&1 || true

  if ! launchctl bootstrap system "$PLIST_DST"; then
    log "bootstrap failed once; retry after bootout/enable"
    launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
    launchctl enable "system/$LABEL" >/dev/null 2>&1 || true
    launchctl bootstrap system "$PLIST_DST" || die "launchctl bootstrap failed"
  fi

  # Kick if already registered but not running.
  launchctl kickstart -k "system/$LABEL" >/dev/null 2>&1 || true

  local i
  for i in $(seq 1 50); do
    if [[ -S "$SOCKET_PATH" ]] && pgrep -f 'exv-helper --service' >/dev/null 2>&1; then
      log "Helper ready: $SOCKET_PATH"
      log "Installed MD5: $(md5 -q "$HELPER_DST" 2>/dev/null || md5sum "$HELPER_DST" | awk '{print $1}')"
      exit 0
    fi
    sleep 0.1
  done

  die "helper did not become ready on $SOCKET_PATH; check /var/log/exv-helper.log"
}

main "$@"
