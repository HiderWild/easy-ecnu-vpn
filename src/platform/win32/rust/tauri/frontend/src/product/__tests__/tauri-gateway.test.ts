import { beforeEach, describe, expect, it, vi } from "vitest";

import type { RuntimeEvent, RuntimeSnapshot } from "../../lib/ipc";
import {
  kernel,
  onStatus,
} from "../../lib/ipc";
import {
  NO_PROFILE_CONNECT_INTENT,
  createProductRuntime,
  tauriProductGateway,
} from "../runtime";
import {
  snapshotConnected,
  snapshotConnecting,
  snapshotIdle,
} from "../../test/fixtures";

let statusListener: ((event: RuntimeEvent) => void) | null = null;
let snapshotReply: RuntimeSnapshot = snapshotIdle();

vi.mock("../../lib/ipc", () => ({
  kernel: {
    connect: vi.fn(async () => ({
      result: { result: "pending" },
      operation_id: "op-1",
    })),
    stop: vi.fn(async () => ({
      result: { result: "pending" },
      operation_id: "op-2",
    })),
    snapshot: vi.fn(async () => snapshotReply),
    coreStatus: vi.fn(async () => "normal"),
    configGet: vi.fn(async () => ({
      items: [
        { key: "username", value: "test-user" },
        { key: "server", value: "vpn-cn.ecnu.edu.cn" },
      ],
    })),
    tunnelAddress: vi.fn(async () => "10.88.88.5"),
  },
  onStatus: vi.fn(async (listener: (event: RuntimeEvent) => void) => {
    statusListener = listener;
    return () => {
      if (statusListener === listener) statusListener = null;
    };
  }),
}));

function emitStatus(snapshot: RuntimeSnapshot, operationId = "op-1"): void {
  statusListener?.({
    monotonic_tick: snapshot.monotonic_tick + 1,
    kind: "transition",
    operation_id: operationId,
    snapshot: { ...snapshot, operation_id: operationId },
  });
}

describe("Tauri 产品网关与产品运行时边界", () => {
  beforeEach(() => {
    statusListener = null;
    snapshotReply = snapshotIdle();
    vi.clearAllMocks();
  });

  it("只通过唯一网关以冻结的空 profile 意图调用 Core connect", async () => {
    await tauriProductGateway.connect(NO_PROFILE_CONNECT_INTENT);
    expect(kernel.connect).toHaveBeenCalledTimes(1);
    expect(kernel.connect).toHaveBeenCalledWith(NO_PROFILE_CONNECT_INTENT);
    expect(Object.isFrozen(NO_PROFILE_CONNECT_INTENT)).toBe(true);
  });

  it("停止和状态订阅也只转发给现有 Core 接口", async () => {
    await tauriProductGateway.stop();
    const listener = vi.fn();
    const unlisten = await tauriProductGateway.onStatus(listener);

    expect(kernel.stop).toHaveBeenCalledTimes(1);
    expect(onStatus).toHaveBeenCalledWith(listener);
    expect(typeof unlisten).toBe("function");
  });

  it("Core 存续状态独立经控制管道命令读取，不把进程枚举暴露给前端", async () => {
    await expect(tauriProductGateway.coreStatus!()).resolves.toBe("normal");
    expect(kernel.coreStatus).toHaveBeenCalledTimes(1);
  });

  it("Core 事件经 ProductRuntime 和 present 交给页面，不由页面重解析", async () => {
    const runtime = createProductRuntime(tauriProductGateway, () => 61_000);
    await runtime.start();
    await runtime.connect();

    emitStatus(snapshotConnecting("applying_platform_tunnel"));

    expect(runtime.state.value).toMatchObject({
      status: "connecting",
      metrics: null,
    });
    expect(runtime.state.value.stages).toHaveLength(8);
    expect(runtime.state.value.stages.filter((stage) => stage.visual === "current")).toHaveLength(1);
    expect(runtime.state.value.stages[5]).toMatchObject({
      label: "写入配置",
      visual: "current",
    });
  });

  it("Core 的已连接统计和代理 TUN 检测沿同一条 presenter 链到达产品状态", async () => {
    const runtime = createProductRuntime(tauriProductGateway, () => 61_000);
    await runtime.start();
    await runtime.connect();

    emitStatus(
      snapshotConnected(
        { rx_rate_bps: 4_096 },
        {
          proxy_tun: {
            detected: true,
            adapters: [
              {
                name: "Mihomo",
                description: "Wintun Userspace Tunnel",
                if_index: 12,
                kind: "proxy_tun",
              },
            ],
            route_policy: "exv-before-proxy-tun",
          },
        },
      ),
    );

    expect(runtime.state.value.status).toBe("connected");
    expect(runtime.state.value.connectionInfo).toEqual({
      account: "test-user",
      vpnServer: "vpn-cn.ecnu.edu.cn",
      campusIp: "10.88.88.5",
    });
    expect(runtime.state.value.metrics).toMatchObject({
      availability: "available",
      downloadRate: "4 KB/s",
    });
    expect(runtime.state.value.proxyTun).toMatchObject({
      status: "detected",
      adapterNames: ["Mihomo"],
      routePolicy: "exv-before-proxy-tun",
    });
    expect(runtime.state.value.metrics).not.toBeNull();
    runtime.dispose();
  });

  it("连接真正进入 connected 后重新读取隧道地址，覆盖连接前尚未分配地址的时序", async () => {
    const tunnelAddress = vi.mocked(kernel.tunnelAddress);
    tunnelAddress
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce("10.88.88.5");
    const runtime = createProductRuntime(tauriProductGateway, () => 61_000);

    await runtime.start();
    await runtime.connect();
    expect(runtime.state.value.connectionInfo.campusIp).toBeNull();

    emitStatus(snapshotConnected());
    await vi.waitFor(() => {
      expect(tunnelAddress).toHaveBeenCalledTimes(3);
      expect(runtime.state.value.connectionInfo.campusIp).toBe("10.88.88.5");
    });
    runtime.dispose();
  });

  it("connected 状态下周期拉取新快照，使速率、累计流量和在线时长持续更新", async () => {
    vi.useFakeTimers();
    try {
      const runtime = createProductRuntime(tauriProductGateway, () => 61_000);
      await runtime.start();
      await runtime.connect();

      emitStatus(snapshotConnected({ rx_rate_bps: 1_024, rx_bytes: 2_048 }));
      snapshotReply = snapshotConnected({ rx_rate_bps: 8_192, rx_bytes: 16_384 });

      await vi.advanceTimersByTimeAsync(1_000);

      expect(kernel.snapshot).toHaveBeenCalledTimes(2);
      expect(runtime.state.value.metrics).toMatchObject({
        downloadRate: "8 KB/s",
        downloadTotal: "16 KB",
      });
      runtime.dispose();
    } finally {
      vi.useRealTimers();
    }
  });

  it("已连接但 Core 没有有效统计时，产品状态标记不可用而不是伪造零值", async () => {
    const runtime = createProductRuntime(tauriProductGateway, () => 61_000);
    await runtime.start();
    await runtime.connect();

    emitStatus(snapshotConnected({}, { stats: null }));

    expect(runtime.state.value.metrics).toEqual({ availability: "unavailable", online: "00:01:00" });
    runtime.dispose();
  });
});
