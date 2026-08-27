// R4 事件→动作映射表：runtime state/event → UI 动作。
//
// 这是前端「事件→动作」的唯一决策源（计划 §0.10 P2-13 / §3 R4）：状态文案、错误
// 显示、按钮可用性、进度指示、operation_id 关联、盲清修复三规则全部落在这里，
// 逐项可查。ConnectPage 只消费本模块的纯函数，不散落各处。
//
// 契约（R1/R1w）：
//   * RuntimeEvent 携带 operation_id（hex16；空 = 无在途操作），镜像
//     snapshot.operation_id；host 以 `OperationLookupKey.operation_id` 关联状态事件。
//   * connect/stop 命令异步受理（pending）：终态/阶段经 `exv://status` 事件驱动，
//     pending 不是失败。
//   * RuntimeState 8 形态 + ConnectPhase 8 级 + 粗粒度（idle/connecting/connected/
//     stopping/failed/reconciling）。

import type { ConnectPhase, RuntimeEvent, RuntimeState, VpnError } from "./ipc";

/** 粗粒度连接阶段（计划 R4：Connecting/Connected/Failed/Stopping/Stopped/Reconciling）。 */
export type CoarsePhase =
  | "idle" // 对应 Stopped / 回空闲
  | "connecting"
  | "awaiting_interaction"
  | "connected"
  | "stopping"
  | "reconciling"
  | "failed";

/** 一个 runtime state 对应的全部 UI 动作（映射表条目）。 */
export interface StateUi {
  /** 主状态文案（badge / 首行）。 */
  label: string;
  /** 粗粒度阶段。 */
  coarse: CoarsePhase;
  /** badge 样式：ok / warn / err / 空。 */
  badgeClass: string;
  /** 环形指示器：off / on / busy。 */
  ring: "off" | "on" | "busy";
  /** 是否展示 8 级连接阶段进度（connecting 时）。 */
  showProgress: boolean;
  /** 连接按钮可用性。 */
  connectEnabled: boolean;
  /** 断开按钮可用性。 */
  stopEnabled: boolean;
}

/** 映射表：runtime state → UI 动作（逐项可查；改动只在这里）。 */
export const STATE_UI: Record<RuntimeState["state"], StateUi> = {
  idle: {
    label: "空闲",
    coarse: "idle",
    badgeClass: "",
    ring: "off",
    showProgress: false,
    connectEnabled: true,
    stopEnabled: false,
  },
  connecting: {
    label: "连接中",
    coarse: "connecting",
    badgeClass: "warn",
    ring: "busy",
    showProgress: true,
    connectEnabled: false,
    stopEnabled: true, // 取消 = Stop（计划 D1）
  },
  awaiting_interaction: {
    label: "认证中",
    coarse: "awaiting_interaction",
    badgeClass: "warn",
    ring: "busy",
    showProgress: true,
    connectEnabled: false,
    stopEnabled: true,
  },
  connected: {
    label: "已连接",
    coarse: "connected",
    badgeClass: "ok",
    ring: "on",
    showProgress: false,
    connectEnabled: false,
    stopEnabled: true,
  },
  stopping: {
    label: "停止中",
    coarse: "stopping",
    badgeClass: "warn",
    ring: "busy",
    showProgress: false,
    connectEnabled: false,
    stopEnabled: false,
  },
  reconciling: {
    label: "同步中",
    coarse: "reconciling",
    badgeClass: "warn",
    ring: "busy",
    showProgress: false,
    connectEnabled: false,
    stopEnabled: true,
  },
  failed_clean: {
    label: "连接失败",
    coarse: "failed",
    badgeClass: "err",
    ring: "off",
    showProgress: false,
    connectEnabled: true,
    stopEnabled: false,
  },
  failed_dirty: {
    label: "连接失败（需恢复）",
    coarse: "failed",
    badgeClass: "err",
    ring: "off",
    showProgress: false,
    connectEnabled: true,
    stopEnabled: false,
  },
};

/** 8 级 ConnectPhase → 中文阶段文案（计划 R4：阶段文案对齐）。 */
export const CONNECT_PHASE_LABELS: Record<ConnectPhase, string> = {
  observing_owned_state: "观察自有状态",
  acquiring_platform_lease: "获取平台租约",
  connecting_control: "连接控制通道",
  awaiting_interaction: "认证中",
  negotiating_tunnel: "协商隧道",
  applying_platform_tunnel: "应用平台隧道",
  attaching_packet_boundary: "挂接数据边界",
  starting_data_plane: "启动数据面",
};

/** 8 级 ConnectPhase 顺序（进度序号 = 下标 + 1）。 */
export const CONNECT_PHASE_ORDER: ConnectPhase[] = [
  "observing_owned_state",
  "acquiring_platform_lease",
  "connecting_control",
  "awaiting_interaction",
  "negotiating_tunnel",
  "applying_platform_tunnel",
  "attaching_packet_boundary",
  "starting_data_plane",
];

/**
 * 稳定错误码 → 友好中文文案。
 *
 * Rust `VpnError` 只向 UI 透传稳定 code 字符串（redaction 政策：自由文本诊断栈永不
 * 进 UI，见 app/src/kernel/wire.rs `vpn_error_from_wire`），故用码表转可读文案。
 */
export const ERROR_CODE_LABELS: Record<string, string> = {
  ERROR_CODE_INVALID_INPUT: "输入无效",
  ERROR_CODE_IDEMPOTENCY_CONFLICT: "重复操作冲突",
  ERROR_CODE_CONNECT_IN_PROGRESS: "已有连接进行中",
  ERROR_CODE_SESSION_BUSY: "会话忙，请稍后重试",
  ERROR_CODE_RECONNECT_ALREADY_QUEUED: "重连已排队",
  ERROR_CODE_CANCELLED_BEFORE_START: "操作已取消",
  ERROR_CODE_AUTHORITY_ALREADY_HELD: "权限已被其他会话持有",
  ERROR_CODE_OWNERSHIP_ACQUISITION_PENDING: "所有权获取中",
  ERROR_CODE_OBSERVED_CONFLICT: "检测到状态冲突",
  ERROR_CODE_JOURNAL_CORRUPT: "日志损坏",
  ERROR_CODE_DATA_PLANE_BACKPRESSURE: "数据面压力过大",
  ERROR_CODE_PACKET_LEASE_ALREADY_ATTACHED: "数据边界已挂接",
  ERROR_CODE_EFFECT_UNKNOWN: "操作结果未知",
  ERROR_CODE_OBSERVATION_FAILED: "状态观测失败",
  ERROR_CODE_UNAUTHORIZED: "认证失败（未授权）",
  ERROR_CODE_DEADLINE_EXCEEDED: "操作超时",
  ERROR_CODE_ACTIVE_ATTEMPT_CANNOT_RECONCILE: "进行中的连接无法恢复",
  ERROR_CODE_ACTIVE_SESSION_CANNOT_RECONCILE: "已连接会话无法恢复",
};

// ---------------------------------------------------------------------------
// 盲清修复三规则（缺陷 B-F1）：何时清 / 何时不清 / 何时显示
// ---------------------------------------------------------------------------
// 规则1（清）：新一轮用户动作发起（connect/stop 点击）或真实 transition 到稳定态
//             （connected / idle）——错误只在这些时刻清除。
// 规则2（不清）：中间态事件（connecting 各阶段 / awaiting_interaction / stopping /
//             reconciling）与同态快照重放不清除已有错误。
// 规则3（显示）：failed_clean / failed_dirty 的 error 与 reconciling 的
//             blocking_error 必须渲染到横幅；一旦显示，后续普通状态事件不覆盖。

/** 稳定态（终态）：到达即认为当前操作告一段落（错误清除 + operation_id 终结标记）。 */
export function isTerminalState(state: RuntimeState): boolean {
  return (
    state.state === "connected" ||
    state.state === "idle" ||
    state.state === "failed_clean" ||
    state.state === "failed_dirty"
  );
}

/** 从 runtime state 提取要展示的错误文案（规则3）；无错误 → null。 */
export function errorOf(state: RuntimeState): string | null {
  switch (state.state) {
    case "failed_clean":
    case "failed_dirty":
      return state.error ? formatError(state.error) : "连接失败";
    case "reconciling":
      return state.blocking_error ? formatError(state.blocking_error) : null;
    default:
      return null;
  }
}

/** 格式化 VpnError：优先稳定 code 的友好文案，回退 message / 原始 code。 */
export function formatError(err: VpnError): string {
  const label = ERROR_CODE_LABELS[err.code];
  if (label) return label;
  const msg = err.message?.trim();
  return msg ? msg : err.code;
}

/** 依据事件更新错误显示（规则1/2/3 的单一实现）。返回应写入 `error` 的新值。 */
export function errorAfterEvent(ev: RuntimeEvent, prevError: unknown): unknown {
  const state = ev.snapshot.runtime;
  // 规则3：失败/reconciling 的错误必须显示（覆盖旧错误——同一显示槽）。
  const shown = errorOf(state);
  if (shown !== null) return shown;
  // 规则1：真实 transition 到稳定态（connected / idle）才清错误。
  if (ev.kind === "transition" && (state.state === "connected" || state.state === "idle")) {
    return null;
  }
  // 规则2：其余（中间态 / 同态快照重放 / 失败终态本身）不清不覆盖。
  return prevError;
}

// ---------------------------------------------------------------------------
// operation_id 关联（R4）：只让当前用户操作的事件驱动连接页 UI
// ---------------------------------------------------------------------------

/** 前端对「当前操作」的关联状态（connect/stop 发起时登记；终态后保持到下次动作）。 */
export interface OpCorrelation {
  /** 最近一次用户动作（connect/stop）拿到的 operation_id；null = 尚无在途操作。 */
  activeOpId: string | null;
  /** 当前操作是否已显示过终态（此后只接受同操作的同态终态重放，不扰动）。 */
  terminalReached: boolean;
}

/**
 * 事件是否应驱动 UI（operation_id 关联过滤）：
 *   * 无在途操作 → 跟随全局（空 id 或终态；带非空 id 的非终态事件是他人操作，不劫持）；
 *   * 有在途操作 → 只认 activeOpId 的事件；已显示终态后只接受同态终态重放；
 *   * 事件无操作 id → 仅终态放行（操作终结、host 清空 id 的收敛事件仍属当前操作）。
 */
export function shouldApplyEvent(ev: RuntimeEvent, corr: OpCorrelation): boolean {
  const op = ev.snapshot.operation_id ?? ev.operation_id ?? null;
  const isTerm = isTerminalState(ev.snapshot.runtime);
  if (corr.activeOpId == null) {
    return op == null || op === "" || isTerm;
  }
  if (op != null && op !== "") {
    if (op !== corr.activeOpId) return false; // 其它操作 → 丢弃（不扰动当前显示）
    if (corr.terminalReached) return isTerm; // 已显示终态：只接受同终态重放
    return true; // 在途：接受进度与终态
  }
  // 事件无操作 id（操作终结、host 清空）→ 仅终态放行（属当前操作收敛）。
  return isTerm;
}

/** 阶段文案（8 级）；未知 phase 回退原文。 */
export function phaseLabelOf(phase: ConnectPhase | string): string {
  return CONNECT_PHASE_LABELS[phase as ConnectPhase] ?? phase;
}

/** 阶段进度序号 0..=7（未识别 → -1）。 */
export function phaseIndexOf(phase: ConnectPhase | string): number {
  const idx = CONNECT_PHASE_ORDER.indexOf(phase as ConnectPhase);
  return idx < 0 ? -1 : idx;
}
