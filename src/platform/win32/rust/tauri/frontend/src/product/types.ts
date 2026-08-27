import type { ConnectPhase } from "../lib/ipc";

/** 阶段在产品界面中的三种明确语义。 */
export type StageVisual = "complete" | "current" | "waiting";

/** 完整模式和极简模式共享的产品模式标识。 */
export type ProductMode = "advanced" | "minimal";

/** 从 Rust 运行状态归一化而来的产品状态。 */
export type ProductStatus =
  | "idle"
  | "connecting"
  | "awaiting"
  | "connected"
  | "stopping"
  | "reconciling"
  | "failed";

/** 仅供视觉层选择语义色和动作，不代表网络业务结果。 */
export type ProductSeverity = "normal" | "attention" | "success" | "error" | "blocking";

export interface ProductStage {
  phase: ConnectPhase;
  label: string;
  visual: StageVisual;
}

/** 尚无稳定 Rust/Tauri 数据口时唯一允许的呈现方式。 */
export interface UnimplementedValue {
  label: "未实现";
  interactive: false;
}

export interface ProductUnimplemented {
  currentUser: UnimplementedValue;
  campusIp: UnimplementedValue;
  vpnServer: UnimplementedValue;
}

/** 连接页可展示的身份与隧道信息；null 表示真实数据源暂未提供该字段。 */
export interface ProductConnectionInfo {
  account: string | null;
  vpnServer: string | null;
  campusIp: string | null;
}

export const EMPTY_PRODUCT_CONNECTION_INFO: ProductConnectionInfo = Object.freeze({
  account: null,
  vpnServer: null,
  campusIp: null,
});

/** 已连接且快照统计有效时出现的真实指标。 */
export interface ProductMetricsAvailable {
  availability: "available";
  online: string;
  downloadRate: string;
  uploadRate: string;
  downloadTotal: string;
  uploadTotal: string;
  latency: string | null;
}

/** 已连接但统计尚不可用；在线时长仍来自已确认的真实会话起点，禁止伪造零流量。 */
export interface ProductMetricsUnavailable {
  availability: "unavailable";
  online: string;
}

export type ProductMetricsDisplay = ProductMetricsAvailable | ProductMetricsUnavailable;

/** 快照携带的真实上游代理 TUN 探测结果；极简模式由组件主动隐藏。 */
export interface ProductProxyTun {
  status: "unknown" | "not_detected" | "detected";
  adapterNames: string[];
  routePolicy: string | null;
}

/** 系统代理模式 wire 值（`SystemProxyDetection.mode`；穷尽解析，未知码归 `"unknown"`）。 */
export type SystemProxyMode = "disabled" | "manual" | "automatic" | "mixed" | "unknown";

/** 快照携带的系统代理检测（S2；仅状态上报——不携带端点 URL/秘密）。 */
export interface ProductSystemProxy {
  /** 系统代理模式；`unknown` = 快照未携带（未检测/检测失败）。 */
  status: SystemProxyMode;
  /** 检测到的系统代理端点数。 */
  endpointCount: number;
  /** EXV 豁免条目是否已合并进系统代理设置。 */
  bypassMerged: boolean;
  /** 四态拓扑（"t0" | "t1" | "t2" | "t3"）；快照未携带时为 null。 */
  topology: string | null;
}

/** 快照携带的自动重连状态（S4；仅状态上报——重连决策在 host 侧 C3a 重连 worker）。 */
export interface ProductReconnect {
  /** 自动重连开关（config auto_reconnect）。 */
  enabled: boolean;
  /** 重连尝试是否正在飞行中。 */
  active: boolean;
  /** 本次连接已执行的重试次数（per-connection；0 = 无）。 */
  currentAttempt: number;
  /** 配置的重试预算（0 = 无限）。 */
  maxAttempts: number;
}

/** SCM 服务状态 wire 值（`ServiceStatus.state`；穷尽解析，未知码归 `"other"`）。 */
export type ServiceScmState =
  | "stopped"
  | "start_pending"
  | "running"
  | "stop_pending"
  | "pause_pending"
  | "paused"
  | "continue_pending"
  | "other";

/** SCM 状态是否运行中（决策输入；替代「`state === "running"` 字符串比较」）。 */
export function isServiceRunning(scmState: ServiceScmState): boolean {
  return scmState === "running";
}

/** SCM 状态是否在过渡（start/stop/pause/continue pending——操作在途，未达终态）。 */
export function isServiceTransitioning(scmState: ServiceScmState): boolean {
  return (
    scmState === "start_pending" ||
    scmState === "stop_pending" ||
    scmState === "pause_pending" ||
    scmState === "continue_pending"
  );
}

/** SCM 状态 → 展示文案（穷尽 switch，覆盖全部 typed 状态与过渡态）。 */
export function serviceStateLabel(scmState: ServiceScmState): string {
  switch (scmState) {
    case "running":
      return "运行中";
    case "start_pending":
      return "启动中…";
    case "stop_pending":
      return "停止中…";
    case "pause_pending":
      return "暂停中…";
    case "paused":
      return "已暂停";
    case "continue_pending":
      return "继续中…";
    case "stopped":
      return "已停止";
    case "other":
      return "状态异常";
  }
}

/** SCM 服务状态的产品语义（S3/D5；仅展示，非授权材料）。 */
export type ProductServiceState =
  /** 尚未查询/查询失败：不得据此自动安装（MED [3]），连接回退 oneshot。 */
  | { kind: "unknown" }
  /** 明确未安装：UI 在此呈现「先装服务再连接 vs 一次性连接」checkbox。 */
  | { kind: "not_installed" }
  /** 已安装：`scmState` 为穷尽 typed 状态（含过渡态）；`healthState` 为 R3 统一健康状态
   *（"healthy" | "scm_orphan" | "installed_unavailable" | "payload_orphan" |
   * "not_installed"，R5 服务连接失败 modal 消费）。 */
  | { kind: "installed"; scmState: ServiceScmState; healthState: string | null };

/** 快照携带的连接模式（D3：只展示，不做路由输入）。 */
export type ProductServiceMode = "auto" | "service" | "oneshot" | "unknown";

/** 产品层服务感知（服务状态 + 模式展示 + M3 决策输入的 checkbox 状态）。 */
export interface ProductService {
  status: ProductServiceState;
  mode: ProductServiceMode;
}

/**
 * 网络资源状态（S1.5 三 owner：路由/网卡/连接，经 StatusPublisher 结构化上报）。
 * 当前快照 wire 未携带 owner 状态字段（proto 冻结，D5 不新增 UI 直连字段）→
 * `available: false` 占位，UI 呈现「未实现」，不伪造 owner 状态。
 */
export type ProductNetworkResources =
  | { available: true; sessionOwner: string; nicOwner: string; routeOwner: string }
  | { available: false };

/** 产品层可直接交给完整模式和极简模式的只读呈现模型。 */
export interface ProductUiState {
  /** Core 控制面两态：仅由已认证控制管道的真实可用性推导。 */
  coreStatus: "normal" | "stopped";
  status: ProductStatus;
  severity: ProductSeverity;
  title: string;
  description: string | null;
  /** 当前失败/恢复错误的稳定码；页面据此选择可执行的处理说明。 */
  errorCode: string | null;
  stages: ProductStage[];
  metrics: ProductMetricsDisplay | null;
  connectionInfo: ProductConnectionInfo;
  proxyTun: ProductProxyTun;
  systemProxy: ProductSystemProxy;
  reconnect: ProductReconnect;
  service: ProductService;
  networkResources: ProductNetworkResources;
  connectEnabled: boolean;
  stopEnabled: boolean;
}
