import { describe, expect, it, vi } from "vitest";

import type {
  ConnectIntent,
  OperationReply,
  RuntimeEvent,
  RuntimeSnapshot,
  ServiceControlAction,
  ServiceControlReply,
} from "../../lib/ipc";
import {
  snapshotConnected,
  snapshotConnecting,
  snapshotFailedClean,
  snapshotIdle,
  snapshotStopping,
} from "../../test/fixtures";
import {
  NO_PROFILE_CONNECT_INTENT,
  createProductRuntime,
  type ProductGateway,
} from "../runtime";
import { createMockRuntime, selectRuntimeSource } from "../mock-runtime";

function statusEvent(
  operationId: string | null,
  snapshot: RuntimeSnapshot,
  kind: RuntimeEvent["kind"] = "transition",
): RuntimeEvent {
  return {
    monotonic_tick: 1,
    kind,
    operation_id: operationId,
    snapshot: { ...snapshot, operation_id: operationId },
  };
}

function createFakeGateway(initialSnapshot: RuntimeSnapshot = snapshotIdle()) {
  const listeners = new Set<(event: RuntimeEvent) => void>();
  let currentOperationId = "current-operation";

  const connect = vi.fn(async (_intent: ConnectIntent): Promise<OperationReply> => ({
    result: { result: "pending" },
    operation_id: currentOperationId,
  }));
  const stop = vi.fn(async (): Promise<OperationReply> => ({
    result: { result: "pending" },
    operation_id: currentOperationId,
  }));
  const snapshot = vi.fn(async (): Promise<RuntimeSnapshot> => initialSnapshot);
  const onStatus = vi.fn(async (listener: (event: RuntimeEvent) => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  });
  const triggerLatencyRefresh = vi.fn(async (): Promise<void> => undefined);
  const serviceControl = vi.fn(
    async (_action: ServiceControlAction): Promise<ServiceControlReply> => ({
      service_status: null,
      ok: true,
      message: "ok",
    }),
  );

  return {
    gateway: {
      connect,
      stop,
      snapshot,
      onStatus,
      triggerLatencyRefresh,
      serviceControl,
    } satisfies ProductGateway,
    connect,
    stop,
    snapshot,
    onStatus,
    triggerLatencyRefresh,
    serviceControl,
    emit(event: RuntimeEvent) {
      for (const listener of listeners) listener(event);
    },
    get currentOperationId() {
      return currentOperationId;
    },
    set currentOperationId(value: string) {
      currentOperationId = value;
    },
  };
}

describe("产品运行时", () => {
  it("常规 Core 状态只消费控制管道结论，已停止时不自动发起连接", async () => {
    const fake = createFakeGateway();
    const coreStatus = vi.fn(async () => "stopped" as const);
    const runtime = createProductRuntime({ ...fake.gateway, coreStatus }, () => 1_000);

    await runtime.start();
    await vi.waitFor(() => {
      expect(runtime.state.value.coreStatus).toBe("stopped");
    });
    expect(coreStatus).toHaveBeenCalledTimes(1);
    expect(fake.connect).not.toHaveBeenCalled();
    runtime.dispose();
  });

  it("连接操作始终发送冻结的空 profile 意图，而不伪造 profile", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway, () => 1_000);

    await runtime.connect();

    expect(Object.isFrozen(NO_PROFILE_CONNECT_INTENT)).toBe(true);
    expect(fake.connect).toHaveBeenCalledWith({ profile_ref: "" });
    expect(fake.connect).toHaveBeenCalledWith(NO_PROFILE_CONNECT_INTENT);
  });

  it("连接请求发出前立即进入连接中状态，失败时恢复可操作状态", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway, () => 1_000);
    await runtime.start();

    let resolveConnect!: (reply: OperationReply) => void;
    fake.connect.mockImplementationOnce(
      () => new Promise<OperationReply>((resolve) => {
        resolveConnect = resolve;
      }),
    );
    const pending = runtime.connect();
    expect(runtime.state.value.status).toBe("connecting");
    expect(runtime.state.value.title).toBe("连接中");
    expect(runtime.state.value.description).toContain("发起连接请求");

    resolveConnect({ result: { result: "pending" }, operation_id: "optimistic-connect" });
    await pending;
    expect(runtime.state.value.status).toBe("connecting");

    fake.currentOperationId = "failed-connect";
    fake.connect.mockRejectedValueOnce(new Error("connect failed"));
    await expect(runtime.connect()).rejects.toThrow("connect failed");
    expect(runtime.state.value.status).toBe("idle");
    expect(runtime.state.value.title).toBe("未连接");
  });

  it("断开请求发出前立即进入断开中状态", async () => {
    const fake = createFakeGateway(snapshotConnected());
    const runtime = createProductRuntime(fake.gateway, () => 1_000);
    await runtime.start();

    let resolveStop!: (reply: OperationReply) => void;
    fake.stop.mockImplementationOnce(
      () => new Promise<OperationReply>((resolve) => {
        resolveStop = resolve;
      }),
    );
    const pending = runtime.stop();
    expect(runtime.state.value.status).toBe("stopping");
    expect(runtime.state.value.title).toBe("断开中");

    resolveStop({ result: { result: "pending" }, operation_id: "optimistic-stop" });
    await pending;
    expect(runtime.state.value.status).toBe("stopping");
  });

  it("serviceControl 直接使用 reply 中的服务状态，不等待第二次快照", async () => {
    const fake = createFakeGateway(snapshotIdle());
    const runtime = createProductRuntime(fake.gateway, () => 1_000);
    await runtime.start();

    fake.serviceControl.mockResolvedValueOnce({
      service_status: {
        installed: true,
        state: "running",
      },
      ok: true,
      message: "服务已就绪",
    });

    const reply = await runtime.serviceControl("install");

    expect(fake.serviceControl).toHaveBeenCalledWith("install");
    expect(fake.snapshot).toHaveBeenCalledTimes(1); // 只由 start() 拉取初始快照
    expect(reply.ok).toBe(true);
    expect(runtime.state.value.service).toMatchObject({
      status: { kind: "installed", scmState: "running" },
    });
  });

  it("serviceControl 没有服务状态时保留现有快照且不伪造状态", async () => {
    const fake = createFakeGateway(snapshotIdle());
    const runtime = createProductRuntime(fake.gateway, () => 1_000);
    await runtime.start();

    fake.serviceControl.mockResolvedValueOnce({
      service_status: null,
      ok: true,
      message: "ok",
    });

    const reply = await runtime.serviceControl("query");

    expect(reply.ok).toBe(true);
    expect(fake.snapshot).toHaveBeenCalledTimes(1);
    expect(runtime.state.value.service.status).toMatchObject({ kind: "unknown" });
  });

  it("初始 snapshot 是产品状态与统计的唯一初始来源", async () => {
    const initial = snapshotConnected({ rx_rate_bps: 2_048, tx_rate_bps: 1_024 });
    const fake = createFakeGateway(initial);
    const runtime = createProductRuntime(fake.gateway, () => 61_000);

    await runtime.start();

    expect(runtime.state.value.status).toBe("connected");
    const metrics = runtime.state.value.metrics;
    expect(metrics?.availability).toBe("available");
    if (metrics?.availability === "available") {
      expect(metrics).toMatchObject({
        downloadRate: "2 KB/s",
        uploadRate: "1 KB/s",
      });
    }
    expect(fake.snapshot).toHaveBeenCalledTimes(1);
    expect(fake.onStatus).toHaveBeenCalledTimes(1);
  });

  it("每秒刷新收到缺失会话起点的已连接快照时，保留已确认的在线时长来源", async () => {
    vi.useFakeTimers();
    try {
      const initial = snapshotConnected();
      const incomplete = {
        ...snapshotConnected(),
        runtime: {
          state: "connected" as const,
          session_established_at_ms: null,
          summary: null,
        },
      };
      const fake = createFakeGateway(initial);
      const runtime = createProductRuntime(fake.gateway, () => 61_000);
      await runtime.start();

      // start() 消费初始快照；下一次轮询模拟后端只更新统计、却漏带会话起点的情况。
      fake.snapshot.mockResolvedValueOnce(incomplete);
      await vi.advanceTimersByTimeAsync(1_000);

      expect(runtime.state.value.metrics).toMatchObject({ online: "00:01:00" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("只接受当前操作的 status snapshot，外来 progress 和 terminal 不得改变状态、统计、错误或终态", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway, () => 61_000);
    await runtime.start();
    await runtime.connect();

    fake.emit(statusEvent(fake.currentOperationId, snapshotConnecting("connecting_control")));
    const beforeExternal = runtime.state.value;

    fake.emit(statusEvent("other-operation", snapshotFailedClean()));
    expect(runtime.state.value).toEqual(beforeExternal);

    fake.emit(statusEvent("other-operation", snapshotConnected({ rx_rate_bps: 8_192 })));
    expect(runtime.state.value).toEqual(beforeExternal);

    fake.emit(statusEvent(fake.currentOperationId, snapshotConnecting("negotiating_tunnel")));
    expect(runtime.state.value.status).toBe("connecting");
    expect(runtime.state.value.stages[4]).toMatchObject({ visual: "current" });
    expect(runtime.state.value.metrics).toBeNull();
  });

  it("接受到当前操作的 status snapshot 后才更新连接统计", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway, () => 61_000);
    await runtime.start();
    await runtime.connect();

    fake.emit(statusEvent(fake.currentOperationId, snapshotConnected({ rx_rate_bps: 4_096 })));

    expect(runtime.state.value.status).toBe("connected");
    const metrics = runtime.state.value.metrics;
    expect(metrics?.availability).toBe("available");
    if (metrics?.availability === "available") {
      expect(metrics.downloadRate).toBe("4 KB/s");
    }
  });

  it("首次进入已连接状态时立即请求一次时延刷新，而不等待 engine 的三分钟周期", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway, () => 61_000);
    await runtime.start();

    fake.emit(statusEvent(null, snapshotConnected()));
    await Promise.resolve();

    expect(fake.triggerLatencyRefresh).toHaveBeenCalledTimes(1);
  });

  it("首次时延刷新取得的陈旧非连接快照不能覆盖刚收到的已连接状态", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway);

    await runtime.start();
    fake.emit(statusEvent(null, snapshotConnected()));

    await Promise.resolve();
    await Promise.resolve();

    expect(fake.triggerLatencyRefresh).toHaveBeenCalledTimes(1);
    expect(runtime.state.value.status).toBe("connected");
  });

  it("延迟刷新经 gateway 触发，随后拉取快照并更新产品状态", async () => {
    const fake = createFakeGateway(snapshotConnected({ rx_rate_bps: 2_048 }));
    const runtime = createProductRuntime(fake.gateway, () => 61_000);
    await runtime.start();

    fake.snapshot.mockResolvedValueOnce(snapshotConnected({ rx_rate_bps: 8_192 }));

    await runtime.triggerLatencyRefresh();

    expect(fake.triggerLatencyRefresh).toHaveBeenCalledTimes(1);
    expect(fake.snapshot).toHaveBeenCalledTimes(2); // start() 一次 + 延迟刷新一次
    const metrics = runtime.state.value.metrics;
    expect(metrics?.availability).toBe("available");
    if (metrics?.availability === "available") {
      expect(metrics.downloadRate).toBe("8 KB/s");
    }
  });

  it("连接和停止命令在调用 gateway 前清除旧错误并重置关联", async () => {
    const fake = createFakeGateway();
    const runtime = createProductRuntime(fake.gateway, () => 61_000);
    await runtime.start();
    await runtime.connect();
    fake.emit(statusEvent(fake.currentOperationId, snapshotFailedClean()));
    expect(runtime.state.value.description).toBe("操作超时");

    fake.currentOperationId = "next-connect";
    await runtime.connect();
    expect(runtime.state.value.description).toContain("发起连接请求");

    fake.emit(statusEvent("next-connect", snapshotConnecting("connecting_control")));
    expect(runtime.state.value.status).toBe("connecting");

    fake.currentOperationId = "stop-operation";
    await runtime.stop();
    expect(fake.stop).toHaveBeenCalledTimes(1);

    const stateBeforeStaleEvent = runtime.state.value;
    fake.emit(statusEvent("next-connect", snapshotConnecting("connecting_control")));
    expect(runtime.state.value).toBe(stateBeforeStaleEvent);

    fake.emit(statusEvent("stop-operation", snapshotStopping()));
    expect(runtime.state.value.description).toBeNull();
    expect(runtime.state.value.status).toBe("stopping");
  });
});

describe("模拟运行时与来源选择", () => {
  it("模拟运行时提供同构状态并显式标记为 mock", () => {
    const runtime = createMockRuntime("connected");

    expect(runtime.source).toBe("mock");
    expect(runtime.state.value.status).toBe("connected");
    const metrics = runtime.state.value.metrics;
    expect(metrics?.availability).toBe("available");
    if (metrics?.availability === "available") {
      expect(metrics.downloadRate).toBeDefined();
    }
  });

  it.each([
    [true, "?preview=1", "mock"],
    [false, "?preview=1", "real"],
    [true, "", "real"],
    [true, "?preview=0", "real"],
  ] as const)("仅在 DEV=%s 且 query=%s 时选择 %s", (dev, search, expected) => {
    expect(selectRuntimeSource(dev, search)).toBe(expected);
  });
});
