#!/usr/bin/env bash
# macos-exv-network-reset.sh — tear down EXV tunnel residue on macOS without reboot.
#
# Removes:
#   - scutil DNS keys State:/Network/Service/exv-*/DNS
#   - IPv4 routes whose interface is an EXV-owned utun (172.20.* address) or
#     matching known campus prefixes installed by EXV split routing
#   - optional: best-effort drop of 172.20 addresses on those utuns
#   - optional: stop local EXV UI/core processes (does not uninstall helper)
#
# Usage:
#   sudo bash scripts/macos-exv-network-reset.sh
#   sudo bash scripts/macos-exv-network-reset.sh --keep-app   # leave EXV running
#   bash scripts/macos-exv-network-reset.sh --dry-run        # print only (some
#                                                            # actions still need root)
#
# Safe to re-run. Prefer this over rebooting when a failed connect leaves
# DNS/routes half-applied.

set -euo pipefail

DRY_RUN=0
KEEP_APP=0
VERBOSE=1

log() { printf '%s\n' "$*"; }
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY: $*"
    return 0
  fi
  if [[ "$VERBOSE" -eq 1 ]]; then
    log "+ $*"
  fi
  eval "$@"
}

need_root() {
  if [[ "$(id -u)" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
    log "ERROR: run with sudo (route/DNS/ifconfig changes need root)."
    log "  sudo bash $0 $*"
    exit 1
  fi
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --keep-app) KEEP_APP=1 ;;
    -q|--quiet) VERBOSE=0 ;;
    -h|--help)
      sed -n '1,25p' "$0"
      exit 0
      ;;
  esac
done

need_root "$@"

log "=== EXV macOS network reset ($(date '+%F %T')) ==="

# ---------------------------------------------------------------------------
# 1) Stop UI/core so they stop re-applying routes (helper stays for service)
# ---------------------------------------------------------------------------
if [[ "$KEEP_APP" -eq 0 ]]; then
  log "-- stopping EXV app/core processes --"
  run "pkill -f '/Applications/EXV.app' 2>/dev/null || true"
  run "pkill -f 'EXV.app/Contents/MacOS/EXV' 2>/dev/null || true"
  run "pkill -f 'exv --mode=core' 2>/dev/null || true"
  run "pkill -f 'build/macos/.*/exv --mode=core' 2>/dev/null || true"
  sleep 0.4
else
  log "-- keeping EXV app (--keep-app) --"
fi

# ---------------------------------------------------------------------------
# 2) scutil: remove every State:/Network/Service/exv-*/DNS key
# ---------------------------------------------------------------------------
log "-- removing EXV scutil DNS keys --"
SCUTIL_LIST=$(scutil <<'EOF' 2>/dev/null | sed -n 's/.*\(State:\/Network\/Service\/exv-[^ ]*\/DNS\).*/\1/p' || true
list
EOF
)
# Also probe common interface names used historically
for iface in utun0 utun1 utun2 utun3 utun4 utun5 utun6 utun7 utun8 utun9 utun10 utun11 utun12 utun13 utun14 utun15 EXV; do
  SCUTIL_LIST+=$'\n'"State:/Network/Service/exv-${iface}/DNS"
done

# Dedup
SCUTIL_LIST=$(printf '%s\n' "$SCUTIL_LIST" | sed '/^$/d' | sort -u)
while IFS= read -r key; do
  [[ -z "$key" ]] && continue
  if scutil --get "$key" &>/dev/null || scutil <<< "show $key" 2>/dev/null | rg -q .; then
    :
  fi
  # Always attempt remove (scutil remove is idempotent-ish)
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY: scutil remove $key"
  else
    scutil <<EOF >/dev/null 2>&1 || true
remove $key
EOF
    log "removed (best-effort): $key"
  fi
done <<< "$SCUTIL_LIST"

# Extra: flush DNS cache
run "dscacheutil -flushcache 2>/dev/null || true"
run "killall -HUP mDNSResponder 2>/dev/null || true"

# ---------------------------------------------------------------------------
# 3) Identify EXV-like utun interfaces (IPv4 172.20.x/16 typical OpenConnect)
# ---------------------------------------------------------------------------
log "-- scanning utun interfaces for EXV tunnel addresses --"
EXV_IFACES=()
while IFS= read -r line; do
  iface=$(echo "$line" | awk -F: '{print $1}')
  [[ -n "$iface" ]] || continue
  EXV_IFACES+=("$iface")
done < <(ifconfig -a 2>/dev/null | awk '
  /^[a-z]/ {
    if (cur != "" && is_exv) print cur
    cur=$1; sub(/:$/,"",cur); is_exv=0
  }
  /inet 172\.20\./ { is_exv=1 }
  END { if (cur != "" && is_exv) print cur }
')

if [[ ${#EXV_IFACES[@]} -eq 0 ]]; then
  log "no 172.20.* utun addresses found (routes may still remain)"
else
  log "EXV-like interfaces: ${EXV_IFACES[*]}"
fi

# ---------------------------------------------------------------------------
# 4) Delete IPv4 routes pointing at those interfaces + known campus prefixes
# ---------------------------------------------------------------------------
log "-- deleting EXV-owned IPv4 routes --"

# Known EXV campus split prefixes (best-effort; delete if present)
KNOWN_PREFIXES=(
  "49.52.4.0/25"
  "59.78.176.0/20"
  "59.78.192.0/21"
  "59.78.199.0/21"
  "59.78.189.128/25"
  "58.198.176.128/25"
  "219.228.60.69/32"
  "219.228.56.0/21"
  "219.228.63.0/21"
  "202.120.80.0/20"
  "222.66.117.0/24"
  # Control-plane host bypass (VPN server) — safe to drop on reset
  "202.120.88.66/32"
)

# If Wi-Fi default is missing (common after wedged dual-TUN sessions), restore
# from DHCP router on en0 without touching mihomo tables.
restore_physical_default_if_missing() {
  if route -n get default >/dev/null 2>&1; then
    log "default route present — leave it"
    return 0
  fi
  local router
  router=$(ipconfig getoption en0 router 2>/dev/null || true)
  if [[ -z "$router" ]]; then
    log "WARN: no en0 DHCP router; cannot restore default (check Wi‑Fi)"
    return 0
  fi
  log "default missing — restoring: route -n add default $router"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY: route -n add default $router"
  else
    route -n add default "$router" 2>/dev/null || \
      route -n change default "$router" 2>/dev/null || true
  fi
}

delete_route() {
  local dest="$1"
  # Try several shapes that route(8) accepts
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "DRY: route -n delete -net $dest"
    return 0
  fi
  if route -n delete -net "$dest" 2>/dev/null; then
    log "deleted route $dest"
    return 0
  fi
  # host route form without mask
  if [[ "$dest" == */32 ]]; then
    local host="${dest%/32}"
    if route -n delete -host "$host" 2>/dev/null; then
      log "deleted host route $host"
      return 0
    fi
  fi
  return 0
}

for p in "${KNOWN_PREFIXES[@]}"; do
  delete_route "$p"
done

# Delete any IPv4 route whose Netif is an EXV-like utun (from netstat)
if [[ ${#EXV_IFACES[@]} -gt 0 ]]; then
  iface_re=$(IFS='|'; echo "${EXV_IFACES[*]}")
  while IFS= read -r line; do
    # netstat -rn columns: Destination Gateway Flags Netif
    dest=$(echo "$line" | awk '{print $1}')
    netif=$(echo "$line" | awk '{print $NF}')
    [[ "$dest" == "Destination" || "$dest" == "Internet:" || -z "$dest" ]] && continue
    [[ "$dest" == "default" ]] && continue
    if echo "$netif" | rg -q "^(${iface_re})$"; then
      # Convert 59.78.176/20 style to CIDR if needed
      if [[ "$dest" == */* ]]; then
        delete_route "$dest"
      elif [[ "$dest" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        delete_route "${dest}/32"
      else
        # compact form like 59.78.176/20 already
        if [[ "$DRY_RUN" -eq 1 ]]; then
          log "DRY: route -n delete -net $dest"
        else
          route -n delete -net "$dest" 2>/dev/null && log "deleted route $dest ($netif)" || true
        fi
      fi
    fi
  done < <(netstat -rn -f inet 2>/dev/null || true)
fi

# ---------------------------------------------------------------------------
# 5) Best-effort: remove 172.20 addresses from EXV utuns / bring down aliases
# ---------------------------------------------------------------------------
log "-- clearing EXV IPv4 addresses on tunnel interfaces --"
for iface in "${EXV_IFACES[@]:-}"; do
  while IFS= read -r addr; do
    [[ -z "$addr" ]] && continue
    if [[ "$DRY_RUN" -eq 1 ]]; then
      log "DRY: ifconfig $iface inet $addr -alias"
    else
      ifconfig "$iface" inet "$addr" -alias 2>/dev/null && log "removed $addr from $iface" || true
    fi
  done < <(ifconfig "$iface" 2>/dev/null | awk '/inet 172\.20\./ {print $2}')
done

# ---------------------------------------------------------------------------
# 5b) Restore physical default if totally missing
# ---------------------------------------------------------------------------
log "-- physical default restore (if missing) --"
restore_physical_default_if_missing

# ---------------------------------------------------------------------------
# 6) Summary
# ---------------------------------------------------------------------------
log "-- post-reset snapshot --"
log "default route:"
route -n get default 2>/dev/null | head -12 || true
log "remaining EXV-ish routes (should be empty):"
netstat -rn -f inet 2>/dev/null | rg '172\.20|49\.52|59\.78|58\.198|202\.120\.8|219\.228|222\.66\.117|utun' || log "(none matched)"
log "DNS head:"
scutil --dns 2>/dev/null | head -20 || true
log "=== done. If the network is still bad, toggle Wi‑Fi or restart Clash, not the Mac. ==="
