import { ref, type InjectionKey, type Ref } from "vue";

import {
  kernel,
  onStatus,
  type ConnectIntent,
  type CoreStatus,
  type OperationReply,
  type RuntimeEvent,
  type RuntimeSnapshot,
  type RuntimeState,
  type ServiceControlAction,
  type ServiceControlReply,
} from "../lib/ipc";
import {
  errorAfterEvent,
  errorOf,
  isTerminalState,
  shouldApplyEvent,
  type OpCorrelation,
} from "../lib/status-map";
import { present } from "./presenter";
import { EMPTY_PRODUCT_CONNECTION_INFO, type ProductConnectionInfo, type ProductUiState } from "./types";

export type StopListening = () => void;

/** 当前 Rust wire 已定义的无 profile 连接意图；不得由页面补造 profile。
 *  R1：安装/连接独立——connect 只携带 profile_ref + secret_payload（安装由 UI 独立发
 *  ServiceControl install）。 */
export const NO_PROFILE_CONNECT_INTENT: ConnectIntent = Object.freeze({
  profile_ref: "",
});

/** 产品层唯一允许的真实业务入口；刻意不包含 onStats。 */
export interface ProductGateway {
  connect(intent: ConnectIntent): Promise<OperationReply>;
  stop(): Promise<OperationReply>;
  snapshot(): Promise<RuntimeSnapshot>;
  /** Core 存续状态：仅由已认证控制管道的可用性判定。 */
  coreStatus?(): Promise<CoreStatus>;
  onStatus(listener: (event: RuntimeEvent) => void): Promise<StopListening>;
  /** T1：请求一次延迟刷新（engine 数据面立即 ping；新延迟经后续快照 stats 到达）。 */
  triggerLatencyRefresh(): Promise<void>;
  /** S3/D5：服务控制（query/install/uninstall/start）。 */
  serviceControl(action: ServiceControlAction): Promise<ServiceControlReply>;
  /** 连接身份与校内地址；真实网关读取 core 配置并探测 EXV 隧道适配器。 */
  connectionInfo?(): Promise<ProductConnectionInfo>;
}

export interface ProductRuntime {
  readonly state: Readonly<Ref<ProductUiState>>;
  readonly source: "real" | "mock";
  start(): Promise<void>;
  connect(): Promise<void>;
  stop(): Promise<void>;
  /**
   * T1：触发一次延迟刷新并拉取最新快照。best-effort：engine 周期探测
   * （每 3 分钟）仍会更新延迟，即使显式刷新失败也不视为业务错误。
   */
  triggerLatencyRefresh(): Promise<void>;
  /**
   * S3/D5：执行服务控制并立即拉取最新快照（post-action 服务状态经 GetSnapshot 反映）。
   * 返回 reply（含 post-action 服务状态 + ok + 人类可读信息）。
   */
  serviceControl(action: ServiceControlAction): Promise<ServiceControlReply>;
  dispose(): void;
}

/** 供后续产品壳注入同一运行时；页面不得直接调用 kernel 或 onStatus。 */
export const PRODUCT_RUNTIME_KEY: InjectionKey<ProductRuntime> = Symbol("product-runtime");

/** Tauri 的真实网关：只转发 Task 3 允许的四个现有接口。 */
export const tauriProductGateway: ProductGateway = {
  connect: (intent) => kernel.connect(intent),
  stop: () => kernel.stop(),
  snapshot: () => kernel.snapshot(),
  coreStatus: () => kernel.coreStatus(),
  onStatus: (listener) => onStatus(listener),
  triggerLatencyRefresh: () => kernel.triggerLatencyRefresh(),
  serviceControl: (action) => kernel.serviceControl(action),
  async connectionInfo(): Promise<ProductConnectionInfo> {
    const [config, campusIp] = await Promise.all([
      kernel.configGet(),
      kernel.tunnelAddress().catch(() => null),
    ]);
    const values = new Map(config.items.map((item) => [item.key, item.value]));
    return {
      account: values.get("username")?.trim() || null,
      vpnServer: values.get("server")?.trim() || null,
      campusIp,
    };
  },
};

type DisplayError = string | null | undefined;

function idleSnapshot(): RuntimeSnapshot {
  return {
    runtime: { state: "idle", last_cleanup_at_ms: null },
    monotonic_tick: 0,
    stats: null,
    proxy_tun: null,
    operation_id: null,
    service_status: null,
    mode: "",
  };
}

function isErrorBearingState(runtime: RuntimeState): boolean {
  return (
    runtime.state === "reconciling" ||
    runtime.state === "failed_clean" ||
    runtime.state === "failed_dirty"
  );
}

function productStateFor(
  snapshot: RuntimeSnapshot,
  now: () => number,
  displayError: DisplayError,
  connectionInfo: ProductConnectionInfo,
  coreStatus: CoreStatus,
): ProductUiState {
  const productState = present(snapshot, now(), connectionInfo);

  // `undefined` 代表没有运行时覆盖：例如已连接时仍可展示 snapshot.summary。
  // `null` 则是用户新操作明确清除了旧错误，避免旧 failed snapshot 再次带回横幅。
  if (displayError !== undefined) {
    return { ...productState, coreStatus, description: displayError };
  }

  return { ...productState, coreStatus };
}

function initialDisplayError(snapshot: RuntimeSnapshot): DisplayError {
  return isErrorBearingState(snapshot.runtime) ? errorOf(snapshot.runtime) : undefined;
}

function nextDisplayError(event: RuntimeEvent, previous: DisplayError): DisplayError {
  const next = errorAfterEvent(event, previous);
  if (typeof next === "string") return next;
  if (next === null) {
    return isErrorBearingState(event.snapshot.runtime) ? null : undefined;
  }
  return undefined;
}

function operationIdOf(reply: OperationReply): string | null {
  const operationId = reply.operation_id?.trim();
  return operationId ? operationId : null;
}

type PendingAction = "connect" | "stop" | null;

/**
 * 用户动作一开始就给产品层一个明确的在途状态。
 *
 * 这不是伪造 core 终态：真正的状态仍由带 operation_id 的 status event 接管；这里只
 * 覆盖 IPC 请求尚未返回这一小段时间，让完整模式和极简模式立即进入对应动画并锁住
 * 动作按钮，而不是停留在旧的 idle/connected 画面上。
 */
function optimisticProductState(base: ProductUiState, pendingAction: PendingAction): ProductUiState {
  if (pendingAction === "connect") {
    return {
      ...base,
      status: "connecting",
      severity: "attention",
      title: "连接中",
      description: "正在发起连接请求。",
      errorCode: null,
      metrics: null,
      connectEnabled: false,
      stopEnabled: false,
    };
  }
  if (pendingAction === "stop") {
    return {
      ...base,
      status: "stopping",
      severity: "attention",
      title: "断开中",
      description: "正在安全撤销连接配置。",
      errorCode: null,
      metrics: null,
      connectEnabled: false,
      stopEnabled: false,
    };
  }
  return base;
}

/**
 * 从真实或测试 gateway 构造统一产品运行时。
 *
 * 状态事件的固定顺序：先过滤，再写入快照/产品状态，再计算错误，最后写 terminal 标记。
 */
export function createProductRuntime(
  gateway: ProductGateway = tauriProductGateway,
  now: () => number = Date.now,
): ProductRuntime {
  let latestSnapshot = idleSnapshot();
  let displayError: DisplayError = undefined;
  let correlation: OpCorrelation = { activeOpId: null, terminalReached: false };
  let latestConnectionInfo: ProductConnectionInfo = EMPTY_PRODUCT_CONNECTION_INFO;
  let coreStatus: CoreStatus = "stopped";
  let unlisten: StopListening | null = null;
  let startPromise: Promise<void> | null = null;
  let liveSnapshotTimer: ReturnType<typeof setInterval> | null = null;
  let liveSnapshotInFlight = false;
  let coreStatusTimer: ReturnType<typeof setInterval> | null = null;
  let coreStatusInFlight = false;
  let connectionInfoInFlight: Promise<void> | null = null;
  let pendingAction: PendingAction = null;
  let disposed = false;

  const state = ref<ProductUiState>(
    productStateFor(latestSnapshot, now, displayError, latestConnectionInfo, coreStatus),
  );

  function writeState(): void {
    const base = productStateFor(latestSnapshot, now, displayError, latestConnectionInfo, coreStatus);
    state.value = optimisticProductState(base, pendingAction);
  }

  /**
   * 接纳一份完整快照。后端的周期统计/探测快照偶尔只携带新的伴生数据，可能暂时
   * 缺失本会话已确认的起点；这种不完整更新不能把在线时长清成横线。只有同为
   * Connected 且新值缺失时才保留旧值，断开/新会话/新正值仍按新快照直接替换。
   */
  function adoptSnapshot(snapshot: RuntimeSnapshot): void {
    const previousRuntime = latestSnapshot.runtime;
    const nextRuntime = snapshot.runtime;
    const previousSessionStart = previousRuntime.state === "connected"
      ? previousRuntime.session_established_at_ms
      : undefined;
    const nextSessionStart = nextRuntime.state === "connected"
      ? nextRuntime.session_established_at_ms
      : undefined;
    if (
      previousRuntime.state === "connected" &&
      nextRuntime.state === "connected" &&
      typeof previousSessionStart === "number" &&
      previousSessionStart > 0 &&
      !(typeof nextSessionStart === "number" && nextSessionStart > 0)
    ) {
      latestSnapshot = {
        ...snapshot,
        runtime: {
          ...nextRuntime,
          session_established_at_ms: previousSessionStart,
        },
      };
      return;
    }
    latestSnapshot = snapshot;
  }

  function refreshConnectionInfo(): Promise<void> {
    if (!gateway.connectionInfo) return Promise.resolve();
    if (connectionInfoInFlight !== null) return connectionInfoInFlight;

    connectionInfoInFlight = (async () => {
      try {
        latestConnectionInfo = await gateway.connectionInfo!();
        writeState();
      } catch {
        // 配置/本机适配器探测失败不应阻断连接状态流；保留上一次已确认的信息。
      } finally {
        connectionInfoInFlight = null;
      }
    })();

    return connectionInfoInFlight;
  }

  function refreshConnectionInfoAfterConnected(): void {
    if (!gateway.connectionInfo) return;
    // 连接请求返回后可能仍有一次连接前的配置/适配器探测在途；connected 事件到达时
    // 不能被这次旧探测吞掉，因此在它完成且地址仍为空时补一次 best-effort 探测。
    void refreshConnectionInfo().then(() => {
      if (!disposed && latestSnapshot.runtime.state === "connected" && latestConnectionInfo.campusIp === null) {
        void refreshConnectionInfo();
      }
    });
  }

  function stopLiveSnapshotRefresh(): void {
    if (liveSnapshotTimer === null) return;
    clearInterval(liveSnapshotTimer);
    liveSnapshotTimer = null;
  }

  function stopCoreStatusRefresh(): void {
    if (coreStatusTimer === null) return;
    clearInterval(coreStatusTimer);
    coreStatusTimer = null;
  }

  /** 常规存续观察只查控制管道；它不会扫描进程，也不会拉起 Core。 */
  async function refreshCoreStatus(): Promise<void> {
    if (disposed || coreStatusInFlight || !gateway.coreStatus) return;
    coreStatusInFlight = true;
    try {
      coreStatus = await gateway.coreStatus();
    } catch {
      // 命令层出错等价于控制管道不可用；恢复只在用户随后点击连接时进行。
      coreStatus = "stopped";
    } finally {
      coreStatusInFlight = false;
      if (!disposed) writeState();
    }
  }

  function startCoreStatusRefresh(): void {
    if (coreStatusTimer !== null || disposed || !gateway.coreStatus) return;
    coreStatusTimer = setInterval(() => {
      void refreshCoreStatus();
    }, 3_000);
  }

  async function refreshLiveSnapshot(): Promise<void> {
    if (
      disposed ||
      liveSnapshotInFlight ||
      latestSnapshot.runtime.state !== "connected"
    ) {
      return;
    }

    liveSnapshotInFlight = true;
    try {
      const snapshot = await gateway.snapshot();
      coreStatus = "normal";
      if (disposed) return;

      // 用户已经断开/进入过渡态时，丢弃晚到的旧快照，避免旧连接数据回写页面。
      if (latestSnapshot.runtime.state !== "connected") return;

      adoptSnapshot(snapshot);
      if (snapshot.runtime.state !== "connected") {
        stopLiveSnapshotRefresh();
      } else if (latestConnectionInfo.campusIp === null) {
        // 隧道地址可能比 connected 事件晚一个调度周期；在实时刷新期间继续
        // best-effort 探测，直到前端真正拿到校内地址。
        void refreshConnectionInfo();
      }
      writeState();
    } catch {
      // 实时指标是 best-effort；一次快照失败不应改变连接状态或弹出错误。
      coreStatus = "stopped";
      writeState();
    } finally {
      liveSnapshotInFlight = false;
    }
  }

  function startLiveSnapshotRefresh(): void {
    if (liveSnapshotTimer !== null || disposed) return;
    liveSnapshotTimer = setInterval(() => {
      void refreshLiveSnapshot();
    }, 1000);
  }

  function resetForUserOperation(action: Exclude<PendingAction, null>): void {
    stopLiveSnapshotRefresh();
    displayError = null;
    correlation = { activeOpId: null, terminalReached: false };
    pendingAction = action;
    writeState();
  }

  function handleStatus(event: RuntimeEvent): void {
    if (!shouldApplyEvent(event, correlation)) return;

    pendingAction = null;
    const wasConnected = latestSnapshot.runtime.state === "connected";
    adoptSnapshot(event.snapshot);
    if (event.snapshot.runtime.state === "connected") {
      startLiveSnapshotRefresh();
      if (!wasConnected) {
        refreshConnectionInfoAfterConnected();
        // engine 的周期探测是低频的；每次新会话额外请求一次真实探测，避免用户进入
        // 已连接界面后还要等待其周期。失败仍由后端周期探测兜底，不能产生未处理拒绝。
        void triggerLatencyRefresh().catch(() => undefined);
      }
    } else {
      stopLiveSnapshotRefresh();
    }
    writeState();

    displayError = nextDisplayError(event, displayError);
    writeState();

    if (isTerminalState(event.snapshot.runtime)) {
      correlation.terminalReached = true;
    }
  }

  async function start(): Promise<void> {
    if (startPromise !== null) return startPromise;

    startPromise = (async () => {
      try {
        const snapshot = await gateway.snapshot();
        coreStatus = "normal";
        adoptSnapshot(snapshot);
        displayError = initialDisplayError(snapshot);
        writeState();
      } catch {
        // UI 本身照常打开，明确显示 Core 已停止；用户点击连接才进入受控恢复路径。
        coreStatus = "stopped";
        writeState();
      }
      await refreshConnectionInfo();

      const stopListening = await gateway.onStatus(handleStatus);
      if (disposed) {
        stopListening();
      } else {
        unlisten = stopListening;
        if (latestSnapshot.runtime.state === "connected") startLiveSnapshotRefresh();
      }
      startCoreStatusRefresh();
      void refreshCoreStatus();
    })();

    try {
      await startPromise;
    } catch (error) {
      startPromise = null;
      throw error;
    }
  }

  async function connect(): Promise<void> {
    resetForUserOperation("connect");
    try {
      // 先派发连接请求，身份/校内地址刷新不能阻塞用户看到连接中的即时反馈。
      const reply = await gateway.connect(NO_PROFILE_CONNECT_INTENT);
      coreStatus = "normal";
      correlation.activeOpId = operationIdOf(reply);
      void refreshConnectionInfo();
    } catch (error) {
      pendingAction = null;
      writeState();
      throw error;
    }
  }

  async function stop(): Promise<void> {
    resetForUserOperation("stop");
    try {
      const reply = await gateway.stop();
      correlation.activeOpId = operationIdOf(reply);
    } catch (error) {
      pendingAction = null;
      writeState();
      throw error;
    }
  }

  /**
   * T1：请求一次延迟刷新并立即拉取最新快照（新延迟经 `stats.latency_ms` 到达）。
   * 不触碰错误/关联状态——这是周期探测，不是用户业务操作。
   */
  async function triggerLatencyRefresh(): Promise<void> {
    await gateway.triggerLatencyRefresh();
    const snapshot = await gateway.snapshot();
    // 状态事件已经确认连接后，立即拉取的 IPC 快照仍可能落后一个调度周期。不能让这份
    // 陈旧非连接快照覆盖新会话，否则界面会闪回 idle 并中止实时统计刷新。
    if (latestSnapshot.runtime.state === "connected" && snapshot.runtime.state !== "connected") return;
    adoptSnapshot(snapshot);
    writeState();
  }

  /**
   * S3/D5：执行服务控制并直接消费 reply 中的 post-action 服务状态。
   * ServiceControlReply 已经携带同一事务结束时的服务状态；这里不再追加 GetSnapshot，
   * 避免 UI 在 SCM 操作已经完成后继续等待第二次 IPC。reply 没有状态时保留现有快照。
   * 不触碰错误/关联状态——服务控制是独立于连接状态机的生命周期操作。
   */
  async function serviceControl(action: ServiceControlAction): Promise<ServiceControlReply> {
    const reply = await gateway.serviceControl(action);
    if (reply.service_status !== undefined && reply.service_status !== null) {
      latestSnapshot = {
        ...latestSnapshot,
        service_status: reply.service_status,
      };
      writeState();
    }
    return reply;
  }

  function dispose(): void {
    disposed = true;
    stopLiveSnapshotRefresh();
    stopCoreStatusRefresh();
    unlisten?.();
    unlisten = null;
  }

  return {
    source: "real",
    state,
    start,
    connect,
    stop,
    triggerLatencyRefresh,
    serviceControl,
    dispose,
  };
}
