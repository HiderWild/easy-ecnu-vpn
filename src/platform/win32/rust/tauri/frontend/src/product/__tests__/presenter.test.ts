import { describe, expect, it } from "vitest";

import { formatBytes, formatLatency, formatOnlineDuration, formatRate } from "../formatters";
import { present } from "../presenter";
import {
  snapshotAwaitingInteraction,
  snapshotConnected,
  snapshotConnecting,
  snapshotFailedClean,
  snapshotFailedDirty,
  snapshotIdle,
  snapshotReconciling,
  snapshotStopping,
  snapshotUnauthorized,
} from "../../test/fixtures";

describe("产品呈现模型", () => {
  it("连接中不暴露速率或累计流量，并列出八个阶段", () => {
    const ui = present(snapshotConnecting("applying_platform_tunnel"), 1_000);

    expect(ui.metrics).toBeNull();
    expect(ui.stages).toHaveLength(8);
    expect(ui.stages.map((stage) => stage.label)).toEqual([
      "检查环境",
      "准备权限",
      "连接控制",
      "用户认证",
      "建立通道",
      "写入配置",
      "启用通道",
      "检查网络",
    ]);
    expect(ui.stages[5]).toMatchObject({
      visual: "current",
      label: "写入配置",
    });
    expect(ui.stages.slice(0, 5).every((stage) => stage.visual === "complete")).toBe(true);
    expect(ui.stages.slice(6).every((stage) => stage.visual === "waiting")).toBe(true);
  });

  it("已连接才显示真实速率、累计流量和在线时长", () => {
    const ui = present(
      snapshotConnected({
        rx_rate_bps: 2_048,
        tx_rate_bps: 1_024,
      }),
      61_000,
    );

    expect(ui.metrics).toMatchObject({
      availability: "available",
      downloadRate: "2 KB/s",
      uploadRate: "1 KB/s",
      online: "00:01:00",
    });
    expect(ui.stages).toEqual([]);
  });

  it("统计流尚未就绪时仍显示连接起点计算出的在线时长", () => {
    const ui = present(snapshotConnected({}, { stats: null }), 61_000);

    expect(ui.metrics).toMatchObject({
      availability: "unavailable",
      online: "00:01:00",
    });
  });

  it("连接账户、VPN 服务器和校内地址只接受运行时提供的真实值", () => {
    const ui = present(snapshotConnected(), 61_000, {
      account: "alice",
      vpnServer: "vpn-cn.ecnu.edu.cn",
      campusIp: "10.88.88.5",
    });

    expect(ui.connectionInfo).toEqual({
      account: "alice",
      vpnServer: "vpn-cn.ecnu.edu.cn",
      campusIp: "10.88.88.5",
    });
    expect(present(snapshotIdle(), 0).connectionInfo).toEqual({
      account: null,
      vpnServer: null,
      campusIp: null,
    });
  });

  it.each([
    ["idle", snapshotIdle(), "idle", "normal"],
    ["awaiting_interaction", snapshotAwaitingInteraction(), "awaiting", "attention"],
    ["stopping", snapshotStopping(), "stopping", "attention"],
    ["reconciling", snapshotReconciling(), "reconciling", "attention"],
    ["failed_clean", snapshotFailedClean(), "failed", "error"],
    ["failed_dirty", snapshotFailedDirty(), "failed", "blocking"],
  ] as const)("将 %s 转换为稳定的产品状态", (_runtimeState, snapshot, status, severity) => {
    const ui = present(snapshot, 10_000);

    expect(ui.status).toBe(status);
    expect(ui.severity).toBe(severity);
    expect(ui.metrics).toBeNull();
  });

  it.each([
    [snapshotFailedClean(), "连接失败", "error"],
    [snapshotFailedDirty(), "需要处理", "blocking"],
  ] as const)("失败状态保留稳定标题、严重度且不显示阶段", (snapshot, title, severity) => {
    const ui = present(snapshot, 10_000);

    expect(ui.title).toBe(title);
    expect(ui.severity).toBe(severity);
    expect(ui.stages).toEqual([]);
  });

  it("保留未授权错误码，供连接页显示明确的处理路径", () => {
    const ui = present(snapshotUnauthorized(), 10_000);

    expect(ui.errorCode).toBe("ERROR_CODE_UNAUTHORIZED");
    expect(ui.description).toBe("认证失败（未授权）");
  });

  it("等待账户确认时保持八阶段，但不把无阶段数据伪造成进度", () => {
    const ui = present(snapshotAwaitingInteraction(), 10_000);

    expect(ui.status).toBe("awaiting");
    expect(ui.stages).toHaveLength(8);
    expect(ui.stages[3]).toMatchObject({ visual: "current", label: "用户认证" });
  });

  it("无效统计不显示为零流量，零延迟只隐藏延迟本身", () => {
    const invalid = present(
      snapshotConnected({ rx_rate_bps: Number.NaN, tx_rate_bps: 1_024 }),
      61_000,
    );
    const negative = present(snapshotConnected({ rx_bytes: -1 }), 61_000);
    const missing = present(snapshotConnected({}, { stats: null }), 61_000);
    const stale = present(snapshotConnected({ phase: "connecting" }), 61_000);
    const zeroLatency = present(
      snapshotConnected({ latency_ms: 0 }, {
        reconnect: { auto_reconnect: true, max_attempts: 3, current_attempt: 0, active: false },
      }),
      61_000,
    );

    expect(invalid.metrics).toEqual({ availability: "unavailable", online: "00:01:00" });
    expect(negative.metrics).toEqual({ availability: "unavailable", online: "00:01:00" });
    expect(missing.metrics).toEqual({ availability: "unavailable", online: "00:01:00" });
    expect(stale.metrics).toEqual({ availability: "unavailable", online: "00:01:00" });
    expect(zeroLatency.metrics).toMatchObject({ availability: "available" });
    if (zeroLatency.metrics?.availability === "available") {
      expect(zeroLatency.metrics.latency).toBeNull();
    }

    const reconnectOff = present(snapshotConnected({ latency_ms: 24 }), 61_000);
    if (reconnectOff.metrics?.availability === "available") {
      expect(reconnectOff.metrics.latency).toBe("24 ms");
    }

    const reconnectOn = present(
      snapshotConnected({ latency_ms: 24 }, {
        reconnect: { auto_reconnect: true, max_attempts: 3, current_attempt: 0, active: false },
      }),
      61_000,
    );
    if (reconnectOn.metrics?.availability === "available") {
      expect(reconnectOn.metrics.latency).toBe("24 ms");
    }
  });

  it("已附加的有效统计不会因为内部序列号为零而被隐藏", () => {
    const ui = present(
      snapshotConnected({ engine_sequence: 0, sample_tick: 0 }),
      61_000,
    );

    expect(ui.metrics).toMatchObject({ downloadRate: "2 KB/s", uploadRate: "1 KB/s" });
  });

  it("只把快照中的真实代理 TUN 检测结果呈现给完整模式", () => {
    const detected = present(
      snapshotConnected({}, {
        proxy_tun: {
          detected: true,
          adapters: [
            {
              name: "Mihomo",
              description: "Wintun Userspace Tunnel",
              if_index: 42,
              kind: "proxy_tun",
            },
          ],
          route_policy: "exv-before-proxy-tun",
        },
      }),
      61_000,
    );
    const unknown = present(snapshotIdle(), 0);

    expect(detected.proxyTun).toMatchObject({ status: "detected", adapterNames: ["Mihomo"] });
    expect(unknown.proxyTun).toMatchObject({ status: "unknown", adapterNames: [] });
  });

  it("把快照系统代理检测映射为产品系统代理感知（known / unknown）", () => {
    const known = present(
      snapshotIdle({
        system_proxy: {
          mode: "automatic",
          endpoint_count: 3,
          bypass_merged: true,
          topology: "t2",
        },
      }),
      0,
    );
    expect(known.systemProxy).toEqual({
      status: "automatic",
      endpointCount: 3,
      bypassMerged: true,
      topology: "t2",
    });

    const manual = present(
      snapshotIdle({
        system_proxy: { mode: "manual", endpoint_count: 1, bypass_merged: false, topology: "t0" },
      }),
      0,
    );
    expect(manual.systemProxy).toMatchObject({ status: "manual", endpointCount: 1, topology: "t0" });

    // 未知/缺省 → unknown 兜底（不伪造模式值）。
    const unknown = present(snapshotIdle(), 0);
    expect(unknown.systemProxy).toEqual({
      status: "unknown",
      endpointCount: 0,
      bypassMerged: false,
      topology: null,
    });

    // 未知模式码 fail-closed → "unknown"。
    const odd = present(
      snapshotIdle({
        system_proxy: { mode: "weird", endpoint_count: 0, bypass_merged: false, topology: "" },
      }),
      0,
    );
    expect(odd.systemProxy).toMatchObject({ status: "unknown", topology: null });
  });

  it("把快照自动重连状态映射为产品重连感知（active / enabled / 缺省）", () => {
    const active = present(
      snapshotIdle({
        reconnect: {
          auto_reconnect: true,
          max_attempts: 5,
          current_attempt: 2,
          active: true,
        },
      }),
      0,
    );
    expect(active.reconnect).toEqual({
      enabled: true,
      active: true,
      currentAttempt: 2,
      maxAttempts: 5,
    });

    const armed = present(
      snapshotIdle({
        reconnect: {
          auto_reconnect: true,
          max_attempts: 0,
          current_attempt: 0,
          active: false,
        },
      }),
      0,
    );
    expect(armed.reconnect).toEqual({
      enabled: true,
      active: false,
      currentAttempt: 0,
      maxAttempts: 0,
    });

    // 缺省 → 全禁用占位（不伪造在途状态）。
    const unknown = present(snapshotIdle(), 0);
    expect(unknown.reconnect).toEqual({
      enabled: false,
      active: false,
      currentAttempt: 0,
      maxAttempts: 0,
    });
  });

  it("把快照服务状态映射为产品服务感知（unknown / not_installed / installed）", () => {
    const unknown = present(snapshotIdle(), 0);
    expect(unknown.service.status).toEqual({ kind: "unknown" });
    expect(unknown.service.mode).toBe("auto");

    const notInstalled = present(
      snapshotIdle({
        service_status: { installed: false, state: "stopped" },
        mode: "auto",
      }),
      0,
    );
    expect(notInstalled.service.status).toEqual({ kind: "not_installed" });

    const running = present(
      snapshotIdle({
        service_status: {
          installed: true,
          state: "running",
          health_state: "healthy",
        },
        mode: "service",
      }),
      0,
    );
    expect(running.service.status).toEqual({
      kind: "installed",
      scmState: "running",
      healthState: "healthy",
    });
    expect(running.service.mode).toBe("service");

    const stopped = present(
      snapshotIdle({
        service_status: { installed: true, state: "stopped" },
        mode: "oneshot",
      }),
      0,
    );
    expect(stopped.service.status).toEqual({
      kind: "installed",
      scmState: "stopped",
      healthState: null, // 快照未携带 health_state → null（R3 透传缺省）
    });
    expect(stopped.service.mode).toBe("oneshot");
  });

  it("SCM 过渡态（start_pending/stop_pending）原样透传为 scmState，不折叠为布尔", () => {
    const starting = present(
      snapshotIdle({
        service_status: { installed: true, state: "start_pending" },
        mode: "service",
      }),
      0,
    );
    expect(starting.service.status).toEqual({
      kind: "installed",
      scmState: "start_pending",
      healthState: null,
    });

    const stopping = present(
      snapshotIdle({
        service_status: { installed: true, state: "stop_pending" },
        mode: "service",
      }),
      0,
    );
    expect(stopping.service.status).toEqual({
      kind: "installed",
      scmState: "stop_pending",
      healthState: null,
    });

    // 未知码 fail-closed → "other"。
    const odd = present(
      snapshotIdle({
        service_status: { installed: true, state: "weird" },
        mode: "service",
      }),
      0,
    );
    expect(odd.service.status).toEqual({
      kind: "installed",
      scmState: "other",
      healthState: null,
    });
  });

  it("未知/空 mode 映射为 unknown，不伪造模式值", () => {
    const unknownMode = present(
      snapshotIdle({ service_status: null, mode: "" }),
      0,
    );
    expect(unknownMode.service.mode).toBe("unknown");
  });

  it("网络资源状态在快照未携带时呈现为占位（不伪造 owner 状态）", () => {
    const ui = present(snapshotIdle(), 0);
    expect(ui.networkResources).toEqual({ available: false });
  });
});

describe("指标格式化", () => {
  it("拒绝无效、负数和零延迟", () => {
    expect(formatBytes(Number.NaN)).toBeNull();
    expect(formatBytes(-1)).toBeNull();
    expect(formatRate(Number.POSITIVE_INFINITY)).toBeNull();
    expect(formatRate(-1)).toBeNull();
    expect(formatLatency(0)).toBeNull();
    expect(formatLatency(-5)).toBeNull();
  });

  it("拒绝负的会话时间和当前时钟，避免伪造在线时长", () => {
    expect(formatOnlineDuration(-1_000, 0)).toBeNull();
    expect(formatOnlineDuration(1_000, -1)).toBeNull();
    expect(formatOnlineDuration(Number.NaN, 1_000)).toBeNull();
    expect(formatOnlineDuration(1_000, Number.POSITIVE_INFINITY)).toBeNull();
  });
});
