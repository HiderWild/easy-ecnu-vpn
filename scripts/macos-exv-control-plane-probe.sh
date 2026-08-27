#!/usr/bin/env bash
# macos-exv-control-plane-probe.sh — one-page diagnostics for EXV X1 (control-plane egress)
#
# Usage:
#   bash scripts/macos-exv-control-plane-probe.sh [vpn-host-or-ip]
#   bash scripts/macos-exv-control-plane-probe.sh 202.120.88.66
#   bash scripts/macos-exv-control-plane-probe.sh vpn-cn.ecnu.edu.cn
#
# Safe / read-only (no route deletion). Paste output into issues.

set -euo pipefail

TARGET="${1:-vpn-cn.ecnu.edu.cn}"

echo "=== EXV control-plane probe $(date '+%F %T') ==="
echo "target=$TARGET"
echo

echo "-- physical default --"
route -n get default 2>&1 | sed -n '1,12p' || true
echo

echo "-- route to target --"
route -n get "$TARGET" 2>&1 | sed -n '1,16p' || true
echo

if [[ ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "-- dig A (system resolver; may be fake-ip under Clash) --"
  (dig +short "$TARGET" A 2>/dev/null || true) | head -5
  echo
fi

echo "-- bulk internet sample (expect utun1024 if mihomo auto-route on) --"
for ip in 1.1.1.1 8.8.8.8; do
  echo -n "$ip -> "
  route -n get "$ip" 2>/dev/null | awk '/interface:|gateway:/{printf "%s ", $0}'
  echo
done
echo

echo "-- IPv4 routes involving utun / 198.18 (first 40) --"
netstat -rn -f inet 2>/dev/null | rg 'utun|198\.18|default' | head -40 || true
echo

echo "-- scutil DNS head --"
scutil --dns 2>/dev/null | head -35 || true
echo

echo "-- EXV scutil keys (if any) --"
echo list | scutil 2>/dev/null | rg 'exv-' || echo "(none)"
echo

echo "-- processes --"
pgrep -lf 'exv|mihomo|clash-verge|verge-mihomo' 2>/dev/null | head -20 || true
echo

echo "-- recent app log (tls/dns/bypass/reconnect) --"
LOG="${HOME}/Library/Application Support/EXV/profile/default/exv.log"
if [[ -f "$LOG" ]]; then
  rg -n 'tls\.(endpoint|connect|resolve|read)|proxy_safe|dns\.apply|network\.config\.details|native\.reconnect|darwin_tls|darwin_resolver|darwin_network' "$LOG" 2>/dev/null | tail -50 \
    || tail -30 "$LOG"
else
  echo "(no $LOG)"
fi
echo
echo "=== end probe ==="
echo "X1 healthy if: route-to-VPN-IP interface is en* (not utun1024), and logs show"
echo "  tls.endpoint.resolved tcp_host=<public IP> without 198.18, plus no tls.read.timeout loops."
