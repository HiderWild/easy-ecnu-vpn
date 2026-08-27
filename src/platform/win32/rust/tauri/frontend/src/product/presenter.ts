import type { ConnectPhase, RuntimeSnapshot, RuntimeState } from "../lib/ipc";
import {
  CONNECT_PHASE_ORDER,
  STATE_UI,
  errorOf,
  phaseIndexOf,
  phaseLabelOf,
} from "../lib/status-map";
import type { CoarsePhase } from "../lib/status-map";
import {
  formatBytes,
  formatLatency,
  formatOnlineDuration,
  formatRate,
  hasUsableConnectedSample,
} from "./formatters";
import { EMPTY_PRODUCT_CONNECTION_INFO } from "./types";
import type {
  ProductMetricsDisplay,
  ProductNetworkResources,
  ProductProxyTun,
  ProductReconnect,
  ProductService,
  ProductServiceMode,
  ProductServiceState,
  ProductSeverity,
  ProductStage,
  ProductStatus,
  ProductSystemProxy,
  ProductUiState,
  ProductConnectionInfo,
  ServiceScmState,
  SystemProxyMode,
} from "./types";

/**
 * Rust 的工程阶段名不直接进入产品界面。未知阶段仍回退现有 `phaseLabelOf`，避免静默捏造文字。
 */
export const PRODUCT_PHASE_LABELS: Record<ConnectPhase, string> = {
  observing_owned_state: "检查环境",
  acquiring_platform_lease: "准备权限",
  connecting_control: "连接控制",
  awaiting_interaction: "用户认证",
  negotiating_tunnel: "建立通道",
  applying_platform_tunnel: "写入配置",
  attaching_packet_boundary: "启用通道",
  starting_data_plane: "检查网络",
};

interface ProductCopy {
  title: string;
  severity: ProductSeverity;
}

const PRODUCT_COPY: Record<RuntimeState["state"], ProductCopy> = {
  idle: { title: "未连接", severity: "normal" },
  connecting: { title: "连接中", severity: "attention" },
  awaiting_interaction: { title: "认证中", severity: "attention" },
  connected: { title: "已连接", severity: "success" },
  stopping: { title: "断开中", severity: "attention" },
  reconciling: { title: "处理中", severity: "attention" },
  failed_clean: { title: "连接失败", severity: "error" },
  failed_dirty: { title: "需要处理", severity: "blocking" },
};

const PRODUCT_STATUS_BY_COARSE_PHASE: Record<CoarsePhase, ProductStatus> = {
  idle: "idle",
  connecting: "connecting",
  awaiting_interaction: "awaiting",
  connected: "connected",
  stopping: "stopping",
  reconciling: "reconciling",
  failed: "failed",
};

function productStatus(runtime: RuntimeState): ProductStatus {
  return PRODUCT_STATUS_BY_COARSE_PHASE[STATE_UI[runtime.state].coarse];
}

function currentPhase(runtime: RuntimeState): ConnectPhase | null {
  if (runtime.state === "connecting") return runtime.phase;
  if (runtime.state === "awaiting_interaction") return "awaiting_interaction";
  return null;
}

function productPhaseLabel(phase: ConnectPhase): string {
  return PRODUCT_PHASE_LABELS[phase] ?? phaseLabelOf(phase);
}

function stagesFor(runtime: RuntimeState): ProductStage[] {
  const current = currentPhase(runtime);
  if (current === null) return [];

  const currentIndex = phaseIndexOf(current);
  if (currentIndex < 0) return [];

  return CONNECT_PHASE_ORDER.map((phase, index) => ({
    phase,
    label: productPhaseLabel(phase),
    visual: index < currentIndex ? "complete" : index === currentIndex ? "current" : "waiting",
  }));
}

function proxyTunFor(snapshot: RuntimeSnapshot): ProductProxyTun {
  const detection = snapshot.proxy_tun;
  if (detection === null || detection === undefined) {
    return { status: "unknown", adapterNames: [], routePolicy: null };
  }

  const adapterNames = detection.adapters
    .map((adapter) => adapter.name.trim())
    .filter((name) => name.length > 0);

  return {
    status: detection.detected ? "detected" : "not_detected",
    adapterNames,
    routePolicy: detection.route_policy.trim() || null,
  };
}

/** 解析 wire `mode` 字符串为穷尽 typed [`SystemProxyMode`]（未知码 fail-closed → "unknown"）。 */
function parseSystemProxyMode(raw: string): SystemProxyMode {
  switch (raw) {
    case "disabled":
    case "manual":
    case "automatic":
    case "mixed":
      return raw;
    default:
      return "unknown";
  }
}

/** S2：快照 `system_proxy` → 产品系统代理感知（null/未知 → `unknown`，不伪造）。 */
function systemProxyFor(snapshot: RuntimeSnapshot): ProductSystemProxy {
  const wire = snapshot.system_proxy;
  if (wire === null || wire === undefined) {
    return { status: "unknown", endpointCount: 0, bypassMerged: false, topology: null };
  }
  return {
    status: parseSystemProxyMode(wire.mode),
    endpointCount: wire.endpoint_count,
    bypassMerged: wire.bypass_merged,
    topology: wire.topology.trim() || null,
  };
}

/** S4：快照 `reconnect` → 产品自动重连感知（null → 全禁用占位，不伪造在途状态）。 */
function reconnectFor(snapshot: RuntimeSnapshot): ProductReconnect {
  const wire = snapshot.reconnect;
  if (wire === null || wire === undefined) {
    return { enabled: false, active: false, currentAttempt: 0, maxAttempts: 0 };
  }
  return {
    enabled: wire.auto_reconnect,
    active: wire.active,
    currentAttempt: wire.current_attempt,
    maxAttempts: wire.max_attempts,
  };
}

function metricsFor(snapshot: RuntimeSnapshot, nowMs: number): ProductMetricsDisplay | null {
  if (snapshot.runtime.state !== "connected") {
    return null;
  }

  // 会话起点由 Connected 状态事实提供；不能因为流量采样尚未抵达而把它隐藏。
  const online = formatOnlineDuration(snapshot.runtime.session_established_at_ms, nowMs) ?? "—";

  if (!hasUsableConnectedSample(snapshot.stats)) {
    return { availability: "unavailable", online };
  }

  const stats = snapshot.stats;
  const downloadRate = formatRate(stats.rx_rate_bps);
  const uploadRate = formatRate(stats.tx_rate_bps);
  const downloadTotal = formatBytes(stats.rx_bytes);
  const uploadTotal = formatBytes(stats.tx_bytes);

  // hasUsableConnectedSample 已验证这四个流量值；这层检查保留为防御式边界，绝不回退为零。
  if (downloadRate === null || uploadRate === null || downloadTotal === null || uploadTotal === null) {
    return { availability: "unavailable", online };
  }

  return {
    availability: "available",
    online,
    downloadRate,
    uploadRate,
    downloadTotal,
    uploadTotal,
    // 延迟来自 engine 的独立隧道探测，并不依赖自动重连；不能因「自动重连关闭」
    // 而丢弃一份已经到达的真实 RTT 样本。
    latency: formatLatency(stats.latency_ms),
  };
}

function connectionInfoFor(info: ProductConnectionInfo): ProductConnectionInfo {
  const clean = (value: string | null | undefined): string | null => {
    const trimmed = value?.trim();
    return trimmed ? trimmed : null;
  };

  return {
    account: clean(info.account),
    vpnServer: clean(info.vpnServer),
    campusIp: clean(info.campusIp),
  };
}

/** 解析 wire `state` 字符串为穷尽 typed [`ServiceScmState`]（未知码 fail-closed → "other"）。 */
function parseServiceScmState(raw: string): ServiceScmState {
  switch (raw) {
    case "stopped":
    case "start_pending":
    case "running":
    case "stop_pending":
    case "pause_pending":
    case "paused":
    case "continue_pending":
      return raw;
    default:
      return "other";
  }
}

/**
 * S3/D5：快照 `service_status`/`mode` → 产品服务感知。
 *
 * MED [3]：`service_status` 为 null（尚未查询/查询失败）→ `unknown`，UI 不得据此
 * 勾选「先装服务再连接」（auto_install 仅在明确「未装」时生效），连接回退 oneshot。
 */
function serviceFor(snapshot: RuntimeSnapshot): ProductService {
  const wire = snapshot.service_status;
  let status: ProductServiceState;
  if (wire === null || wire === undefined) {
    status = { kind: "unknown" };
  } else if (!wire.installed) {
    status = { kind: "not_installed" };
  } else {
    status = {
      kind: "installed",
      scmState: parseServiceScmState(wire.state),
      healthState: wire.health_state?.trim() || null,
    };
  }
  const mode: ProductServiceMode =
    snapshot.mode === "auto" || snapshot.mode === "service" || snapshot.mode === "oneshot"
      ? snapshot.mode
      : "unknown";
  return { status, mode };
}

/** 网络资源状态（S1.5 三 owner）：快照 wire 未携带 → `available: false` 占位，不伪造。 */
function networkResourcesFor(): ProductNetworkResources {
  return { available: false };
}

function descriptionFor(runtime: RuntimeState): string | null {
  if (runtime.state === "connected") {
    const summary = runtime.summary?.trim();
    return summary || null;
  }

  return errorOf(runtime);
}

function errorCodeFor(runtime: RuntimeState): string | null {
  switch (runtime.state) {
    case "failed_clean":
    case "failed_dirty":
      return runtime.error?.code?.trim() || null;
    case "reconciling":
      return runtime.blocking_error?.code?.trim() || null;
    default:
      return null;
  }
}

/** 将唯一业务事实 `RuntimeSnapshot` 翻译为 UI 不再自行猜测的产品呈现状态。 */
export function present(
  snapshot: RuntimeSnapshot,
  nowMs: number,
  connectionInfo: ProductConnectionInfo = EMPTY_PRODUCT_CONNECTION_INFO,
  coreStatus: ProductUiState["coreStatus"] = "normal",
): ProductUiState {
  const runtime = snapshot.runtime;
  const stateUi = STATE_UI[runtime.state];
  const copy = PRODUCT_COPY[runtime.state];
  const reconnect = reconnectFor(snapshot);

  return {
    coreStatus,
    status: productStatus(runtime),
    severity: copy.severity,
    title: copy.title,
    description: descriptionFor(runtime),
    errorCode: errorCodeFor(runtime),
    stages: stagesFor(runtime),
    metrics: metricsFor(snapshot, nowMs),
    connectionInfo: connectionInfoFor(connectionInfo),
    proxyTun: proxyTunFor(snapshot),
    systemProxy: systemProxyFor(snapshot),
    reconnect,
    service: serviceFor(snapshot),
    networkResources: networkResourcesFor(),
    connectEnabled: stateUi.connectEnabled,
    stopEnabled: stateUi.stopEnabled,
  };
}
