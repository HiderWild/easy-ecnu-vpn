# EXV Unreleased

本文件用于累计下一次正式发布前的所有变更。每个提交都应更新本文件，正式打包时再迁移到对应的 `docs/RELEASE_NOTES_<version>.md`。

## Added

- feat(ui/win32): 前端自有设置与体验功能（前后端设置项显式切割）——
  纯 UI 行为偏好存 `%LOCALAPPDATA%\EXV\profile\default\ui-preferences.json`
  （字段名照抄 C++ 宿主偏好契约；首次运行一次性导入旧 `close-preference.json`），
  修改不走 core config，core 配置白名单不变：
  * 开机自动运行（HKCU Run key，用户侧无提权）
  * 启动静默（prefs 常态 + `--silent` 单次参数）：启动不弹窗仅托盘驻留
  * 连接后最小化到托盘（进入已连接自动隐藏窗口）
  * 通断托盘气泡通知（自绘 Shell_NotifyIcon NIF_INFO；对齐 C++ 壳行为）
  * 启动时自动连接（首快照空闲即发起一次）
  * 关闭按钮行为三选（smart 误关保护宽限 / tray / quit），替代原硬编码隐藏
  * 自管托盘（替换 tauri tray：左键唤出、右键菜单 显示/退出，退出走 O3 停机）

- docs(plan): active macOS root-cause fix plan for “connected but machine
  offline” + TLS flapping under Clash TUN —  
  `docs/superpowers/plans/2026-07-14-macos-network-breakage-root-cause-fix-plan.md`
  (R-DNS gate, bypass cache, TLS error classification, TransportOnly, resolve
  cache; Phase 1–5 checklist).
- fix(darwin/core): implement network-breakage plan Phases 1–3:
  DNS apply requires match domains (never campus DNS as global); DNS failure
  does not roll back routes; server_bypass session cache across re-apply;
  Darwin TLS read timeout code `tls_read_timeout`; recoverable disconnect
  classification; `transport.interrupted` maps to native reconnect (not full
  rebuild); proxy-safe connect-host cache for TransportOnly re-auth; helper
  prepare no longer uses process-global utun fd stash.
- chore(macos): add `scripts/macos-exv-network-reset.sh` to clear EXV DNS keys,
  split routes, and tunnel addresses without rebooting.
- docs(macos): Darwin architecture topology + experiment ledger vs OpenConnect
  (`docs/superpowers/plans/2026-07-14-macos-darwin-architecture-topology-and-lessons.md`),
  cross-cuts X1–X8, reset-script vs mihomo boundaries.
- docs(plan): active X1 control-plane egress root-cause plan  
  `docs/superpowers/plans/2026-07-15-macos-x1-control-plane-egress-root-cause-plan.md`.
- chore(macos): richer Darwin diagnostics — `darwin_tls` / `darwin_resolver` /
  `darwin_network` / `tls.endpoint.*` / `dns.apply.*` log codes;  
  `scripts/macos-exv-control-plane-probe.sh` for one-page X1 probes.
- fix(darwin): X1 control-plane egress — Network.framework
  `nw_parameters_require_interface` on preferred physical if; after
  server_bypass ensure, best-route probe + re-ensure via physical default
  when still on intercept utun; logs `control_plane.path.probe_*`.
- fix(darwin): inject proxy-safe connect-host resolve + preferred_outbound_if
  into `default_native_engine_dependencies()` so desktop **prepared handshake**
  (NativeHandshakeJob) no longer uses resolver=identity under Clash fake-ip
  (root cause of post-connect tls_read_timeout / UI drop to disconnected).
- fix(darwin): server_bypass is a **global** /32 via physical default
  (`route get -ifscope en0`), not RTF_IFSCOPE; rejects utun/proxy uplinks so
  VPN server IPs inside campus CIDRs (e.g. 202.120.88.66 in 202.120.80.0/20)
  do not hairpin CSTP into EXV/mihomo; logs `control_plane.bypass.*`.
- fix(macos): network-reset restores missing en0 default from DHCP router.
- docs(macos): diagnosis that selective split does not install default route;
  machine-offline feel is dual-TUN + control-plane path, not utun smash-all
  (`docs/superpowers/plans/2026-07-15-macos-selective-routing-vs-machine-offline-diagnosis.md`).
- docs(macos): full split-tunnel + control-plane rules R1–R12 (pin VPN server
  host via physical path for session; Windows comparison not magic immunity;
  system-proxy vs TUN: bypass list vs routing — not auto-implemented)
  (`docs/superpowers/plans/2026-07-15-macos-split-tunnel-control-plane-full-rules.md`).
- docs: cross-platform proxy topology network framework (T0–T3: none /
  system-proxy / peer-TUN / mixed; detect; exemption+capture modes; guard
  via config notify+poll; dual-platform architecture)
  (`docs/superpowers/plans/2026-07-15-exv-proxy-topology-network-framework-design.md`).
- fix(core): derive DNS match domain as `ecnu.edu.cn` (not broad `edu.cn`);
  cap native TransportOnly reconnect attempts (retry_limit default 3 when 0).
- macOS Settings → System → Install Service now prompts via `osascript` and runs `exv-helper --install-service`, installing LaunchDaemon `com.exv.helper` under `/Library/Application Support/EXV/Helper/`.
- Added formal and development Windows package naming rules: formal setup artifacts use `EXV-<version>-windows-x64-setup.exe`, while development packages use auto-incrementing `EXV-<version>-dev.<n>-windows-x64-setup.exe` names.
- Added the native DTLS policy contract and session metadata fields for DTLS mode, active data channel, and fallback count.
- Added a native UDP datagram socket boundary for DTLS with platform implementations that preserve native timeout/error codes.
- Added a build-flagged DTLS channel scaffold so the OpenSSL backend can be compiled only when explicitly enabled.
- Added CSTP parsing for legacy DTLS master-secret metadata with session JSON hex output.
- Added DTLS data-channel selection with safe CSTP/TLS fallback and stable active-channel metadata.
- Added an OpenSSL-gated DTLS channel backend skeleton with safe exporter fallback.
- Added DTLS runtime fallback metadata updates and auto-mode cooldown tracking.
- Exposed native DTLS data-channel status and fallback details through core, desktop, and WebUI status contracts.
- Added a dashboard rail DTLS status summary beside the connection status so users can see whether traffic is using DTLS, CSTP/TLS, or fallback.
- Added native connection data monitoring with total upload/download counters, dashboard upload/download speed labels, and a lightweight DPD-derived reference latency indicator.

## Fixed

- fix(macos): make Darwin tunnel route installation idempotent (RTM ensure /
  delete+add on EEXIST) so split routes succeed under Clash coexistence and
  reconnect races instead of failing with system_error=17.
- fix(helper): always retire session leases after cleanup attempts even when
  platform resource cleanup is partial, preventing permanent
  `session_conflict` / empty session_id on the next connect.
- fix(helper): reclaim leftover sessions automatically before StartSession so
  a prior `cleanup_partial` cannot permanently block new connects.
- fix(darwin): make platform tunnel cleanup best-effort end-to-end so a failed
  DNS restore no longer skips utun address/adapter teardown.
- fix(darwin): probe free utun control units when the first `connect()` is busy
  so core-side packet-device open no longer fails with
  `failed to connect utun control socket` under Clash/AnyConnect coexistence.
- fix(darwin): hand privileged helper-owned utun fds to the unprivileged core
  via SCM_RIGHTS after PrepareTunnelDevice, so the packet loop no longer needs
  PF_SYSTEM connect (which macOS rejects with EPERM for non-root).
- fix(darwin): install campus split routes as global (not RTF_IFSCOPE) so EXV
  sits in front of Clash/mihomo TUN for school prefixes, while other traffic
  still falls through to the proxy/system default.
- fix(core/darwin): always install a server-bypass host route for the configured
  VPN server toward the physical uplink when possible, reducing TLS read
  timeouts under concurrent proxy TUN.
- fix(core): resolve VPN server hostnames to IPv4 before installing server
  bypass routes (hostname strings are rejected by Darwin route install).
- fix(darwin): do not fail ApplyTunnelConfig when Clash still covers a campus
  prefix via a wider route after our more-specific EXV route was installed
  (false EEXIST from best-route ownership checks).
- fix(macos): stop Dock/Cmd-Q quit from SIGSEGV by keeping WKWebView/AppKit
  teardown outside the outer autoreleasepool and avoiding re-entrant
  [NSWindow close] during the hand-rolled run loop exit.
- fix(core): proxy-safe TLS connect host — Production transport can resolve
  TCP destination via injected resolver while keeping SNI as the VPN hostname
  (root fix for Clash fake-ip CSTP timeouts).
- fix(darwin): shared `proxy_safe_resolver` (bind physical if + public DNS,
  filter 198.18/19) used for both TLS connect host and server_bypass.
- fix(core/darwin): transport-only reconnect — keep utun/packet device and
  helper session across recoverable TLS loss; stop ~15s full route rebuild thrash.
- fix(darwin): DeviceConfig.adopt_fd for helper SCM_RIGHTS utun handoff (no
  unprivileged EPERM create path when fd is available).
- fix(core): surface helper StartSession error_code/message instead of only
  reporting an empty session_id.
- chore(macos): add `scripts/install-macos-helper.sh` for reliable local
  LaunchDaemon helper refresh after desktop builds.
- fix(macos): replace deprecated SecureTransport TLS with Network.framework.
  SSLHandshake OSStatus -50 on modern macOS is fixed by using Apple's
  supported TLS stack for CSTP control channel.
- Hid password reveal controls until the corresponding password field contains real input, and reset reveal state when the field is cleared.
- Added horizontal breathing room to the titlebar theme mode buttons so their labels no longer sit too close to the segmented-control edges.
- Fixed first-run onboarding when local user data is empty by reusing the quick-start request flow after initial config loading, so a missed startup event no longer leaves the app on the dashboard without the quick setup guide.
- Hardened quick-start onboarding against false first-run detection and duplicate startup events by distinguishing failed config loads from loaded-empty credentials, requiring auth/settings loads to succeed before frontend fallback onboarding, ignoring duplicate quick-start SSE while a prompt is active, and suppressing repeated prompts after the user skips the guide during the current session.
- Protected the quick-start form from background refresh races so late auth/settings/route reloads do not overwrite fields after the user has started editing.
- Removed redundant quick-start explanatory copy and widened custom setup into a denser multi-column layout instead of increasing dialog height.
- Persisted quick-start skip/completion state across launches, reset that state when the user clears configuration, and added a default-on helper service installation option to quick/custom setup.
- Reworked quick-start custom mode with compact VPN server, reconnect, startup, tray, route, and close-window settings, removed MTU/DTLS from the onboarding flow, and added compact theme/accent controls to quick start.
- Prevented quick-start onboarding from being dismissed by clicking the modal scrim; users must now skip, import, or complete setup explicitly.
- Moved the quick-start mode switch to the modal banner as "brief/custom", placed personalization controls at the bottom of the form as a single-line theme/accent control, moved close-window behavior into the first custom column, disabled quick-start body scrolling, hid launch-at-login from quick mode, and made route editing use a compact explicit add field with an add button and remove-only buttons.
- Routed quick-start helper service setup through the foreground service operation so onboarding installs or repairs prerequisites instead of failing on stale "service unavailable" status.
- Hardened non-DTLS native transport handling so TLS read timeouts retain WSA timeout codes, missing VPN credentials fail instead of simulating a connection, helper keepalive pipe loss is surfaced in session health, and release helper packaging requires packaged Wintun unless a dev override is set.
- Treated Wintun no-packet results as idle packet reads rather than terminal packet-device failures, while preserving coordinator-owned recovery for real transport and helper-loss reconnects.
- Hardened helper initialization so a transient disconnect during the initial helper `Hello` is logged, reconnected, and retried once before the connection is failed.
- Fixed one-shot helper connection startup by preventing core registry status persistence from sending `Inspect` before the helper's required initial `Hello` request.
- Kept the OpenSSL DTLS backend behind the DTLS build flag without adding OpenSSL headers to protocol-layer sources.
- Fixed native DTLS setting propagation so the desktop DTLS toggle reaches the native engine instead of being forced to CSTP/TLS by the config mapper.
- Fixed Windows helper-service cleanup so the packaged helper performs stable-payload removal, while a helper launched from the stable payload refuses to delete its own mapped executable.
- Fixed portable Windows package smoke validation so an existing host helper with a different payload is reported as non-destructive skipped host state, while the administrator installed-service lane still requires an exact payload hash match.
- fix(macos): assign utun IPv4 (SIOCAIFADDR) and bring interface up before
  installing split routes. Fixes ENETUNREACH (51) on RTM_ADD.
- fix(macos): prefer physical default route for server bypass when best-route
  points at fake-ip utun (e.g. 198.18.0.0/15).

## Diagnostics

- Added Windows adapter route diagnostics that flag Clash/Mihomo proxy TUN interfaces before applying VPN network configuration.
- Added helper IPC diagnostics for pipe connect/write/flush/read/timeout failures, helper daemon request/response failures, one-shot helper launch failures, and Windows helper service status/start failures.
- Added a DTLS live-validation template and Windows network diagnostics collection script for disabled/auto/enabled performance comparisons.
- feat(macos): elevated service install/uninstall/repair now async via fork+waitpid, matching Windows ShellExecuteEx pattern.
- feat(helper): structured result file (`--result-file`) replaces exit-code-only error mapping for elevated operations.
- fix(macos): `run_command_silent` prevents subprocess stdout from polluting the core↔UI RPC pipe (systemic fix, affects scutil/ifconfig/osascript).
- fix(macos): helper socket moved to `/var/run/exv-helper/` subdirectory.
  macOS `/var/run` is group-writable (`drwxrwxr-x root:daemon`), which the
  IPC security policy rejects. A dedicated subdirectory at `0755 root:wheel`
  satisfies the policy, matching macOS conventions like `/var/run/ssh/`.
