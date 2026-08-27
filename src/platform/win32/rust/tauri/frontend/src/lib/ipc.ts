// Typed IPC wrappers: Tauri Command (invoke) + Event (listen).
// 契约来源：app/src/kernel/{commands,events,state,logs}.rs（P4-a 骨架）。
// 前端重写（O2）：不复用 C++ webui/ 代码。

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ---- 运行时状态（镜像 app/src/kernel/state.rs） ----

export type ConnectPhase =
  | "observing_owned_state"
  | "acquiring_platform_lease"
  | "connecting_control"
  | "awaiting_interaction"
  | "negotiating_tunnel"
  | "applying_platform_tunnel"
  | "attaching_packet_boundary"
  | "starting_data_plane";

export interface VpnError {
  code: string;
  message: string;
}

export type RuntimeState =
  | { state: "idle"; last_cleanup_at_ms?: number | null }
  | { state: "connecting"; phase: ConnectPhase; attempt_id?: string | null; phase_index: number }
  | { state: "awaiting_interaction"; attempt_id?: string | null; prompt_deadline_ms?: number | null }
  | { state: "connected"; session_established_at_ms?: number | null; summary?: string | null }
  | { state: "stopping"; reason?: string | null }
  | { state: "reconciling"; blocking_error?: VpnError | null }
  | { state: "failed_clean"; error?: VpnError | null }
  | { state: "failed_dirty"; error?: VpnError | null; has_obligation: boolean };

/** 检测到的上游代理 TUN 适配器（C5-wire；镜像 app/src/kernel/state.rs）。 */
export interface ProxyTunAdapter {
  /** 友好名称（如 "Mihomo" / "Meta"）。 */
  name: string;
  /** 接口描述（如 "Wintun Userspace Tunnel"）。 */
  description: string;
  /** IPv4 接口索引。 */
  if_index: number;
  /** 适配器种类（当前恒为 "proxy_tun"）。 */
  kind: string;
}

/** 上游代理 TUN 检测结果（C5-wire；仅状态上报，不改行为）。 */
export interface ProxyTunDetection {
  /** 是否检测到至少一个上游代理 TUN 适配器。 */
  detected: boolean;
  /** 检测到的适配器（detected=false 时为空）。 */
  adapters: ProxyTunAdapter[];
  /** 共存路由策略："exv-before-proxy-tun" | "normal"。 */
  route_policy: string;
}

/** 系统代理检测结果（S2；仅状态上报，不携带端点 URL/秘密——只有计数与短枚举串）。 */
export interface SystemProxyDetection {
  /** 系统代理模式："disabled" | "manual" | "automatic" | "mixed"。 */
  mode: string;
  /** 检测到的系统代理端点数。 */
  endpoint_count: number;
  /** EXV 豁免条目是否已合并进系统代理设置。 */
  bypass_merged: boolean;
  /** 四态拓扑（(proxy_present, tunnel_present) 的纯函数分类）："t0" | "t1" | "t2" | "t3"。 */
  topology: string;
}

/** 自动重连状态（S4；仅状态上报——重连决策在 host 侧 C3a 重连 worker）。 */
export interface ReconnectStatus {
  /** 自动重连开关（config auto_reconnect）。 */
  auto_reconnect: boolean;
  /** 配置的重试预算（config auto_reconnect_max_attempts；0 = 无限）。 */
  max_attempts: number;
  /** 本次连接已执行的重试次数（per-connection；0 = 无）。 */
  current_attempt: number;
  /** 重连尝试是否正在飞行中。 */
  active: boolean;
}

/** win32 engine SCM 服务状态（S3/D5；仅状态展示，非授权材料——服务存在性不构成
 * capability，peer 身份只来自验证过的传输元数据 + PSK）。 */
export interface ServiceStatus {
  /** 服务是否已在 SCM 注册。 */
  installed: boolean;
  /** SCM 服务状态："stopped" | "start_pending" | "stop_pending" | "running" | "other"。 */
  state: string;
  /** R3 统一服务健康状态："healthy" | "scm_orphan" | "installed_unavailable" |
   * "payload_orphan" | "not_installed"；host 未派生时为空。 */
  health_state?: string | null;
}

export interface RuntimeSnapshot {
  runtime: RuntimeState;
  monotonic_tick: number;
  /** stats-wire 方案 A：快照携带最新归一化统计；null = 尚无样本。 */
  stats?: RuntimeStats | null;
  /** C5-wire：快照携带上游代理 TUN 检测；null = 未探测/探测失败。 */
  proxy_tun?: ProxyTunDetection | null;
  /**
   * R1/R4：本快照所属的 in-flight 连接/停止操作 id（hex16，32 字符）；null/空 = 无
   * 在途操作。前端据此只让「当前用户操作」的事件驱动 UI（旧操作迟到事件不扰动显示）。
   */
  operation_id?: string | null;
  /** S3/D5：快照携带的 win32 engine SCM 服务状态；null = 尚未查询/查询失败。仅展示。 */
  service_status?: ServiceStatus | null;
  /** S3/D3：当前连接模式 "auto" | "service" | "oneshot"；只展示，不做路由输入。 */
  mode?: string | null;
  /** S2：快照携带的系统代理检测；null = 未检测/检测失败。仅状态上报。 */
  system_proxy?: SystemProxyDetection | null;
  /** S4：快照携带的自动重连状态；null = 重连不适用/从未建立连接。仅状态上报。 */
  reconnect?: ReconnectStatus | null;
}

export interface RuntimeEvent {
  monotonic_tick: number;
  kind: "snapshot" | "transition";
  snapshot: RuntimeSnapshot;
  /** R1/R4：本事件所属操作 id（镜像 snapshot.operation_id）；null/空 = 无在途操作。 */
  operation_id?: string | null;
}

export type OperationResult =
  | { result: "pending" }
  | { result: "succeeded"; effect_id?: string | null; authority_epoch?: number | null }
  | { result: "failed"; error?: VpnError | null };

export interface OperationReply {
  result: OperationResult;
  /** R4：本命令生成的操作 id（hex16）；null = 未产生/被拒（无状态事件关联）。 */
  operation_id?: string | null;
}

// ---- 运行期统计（镜像 app/src/kernel/stats.rs + host stats.rs::RuntimeStats） ----

/** 统计采样时刻的粗粒度连接阶段（proto StatsPhase）。 */
export type StatsPhase =
  | "unspecified"
  | "idle"
  | "connecting"
  | "connected"
  | "stopping"
  | "failed";

/** 归一化后的运行期统计（host core 权威；rx/tx_rate_bps 为累计增量 / 时间间隔）。 */
export interface RuntimeStats {
  /** 累计接收字节（engine 权威）。 */
  rx_bytes: number;
  /** 累计发送字节（engine 权威）。 */
  tx_bytes: number;
  /** 归一化接收速率（bytes/sec）。 */
  rx_rate_bps: number;
  /** 归一化发送速率（bytes/sec）。 */
  tx_rate_bps: number;
  /** 往返延迟（ms；0 = 未知）。 */
  latency_ms: number;
  /** 采样时刻的连接阶段。 */
  phase: StatsPhase;
  /** engine 样本序号。 */
  engine_sequence: number;
  /** 发布时的事件总线 tick（与状态事件同一 tick 轴；0 = 尚未发布）。 */
  sample_tick: number;
}

// ---- 日志（镜像 app/src/kernel/logs.rs） ----

export interface LogEvent {
  level: "info" | "warn" | "error" | string;
  component: string;
  code: string;
  message: string;
  fields: Record<string, string>;
  timestamp_ms: number;
}

export interface LogChunk {
  events: LogEvent[];
  next_after_seq: number;
  has_more: boolean;
}

export interface LogsClearReply {
  cleared: boolean;
  removed_entries: number;
}

// ---- Command 参数 ----

export interface ConnectIntent {
  profile_ref: string;
  secret_payload?: string | null;
}

// ---- 服务控制（S3/D5：KernelControl.ServiceControl） ----

/** ServiceControl 的 action：query 非提权读；install/uninstall/start 走 runas 提权 seam。 */
export type ServiceControlAction = "query" | "install" | "uninstall" | "start";

/** ServiceControl 回复：post-action 服务状态 + 结果 + 人类可读信息（无秘密/栈）。 */
export interface ServiceControlReply {
  service_status?: ServiceStatus | null;
  ok: boolean;
  message: string;
}

export interface ConfigItem {
  key: string;
  value: string;
}

export interface ConfigPayload {
  items: ConfigItem[];
}

/** UI 对 Core 控制面的仅有两种结论：正常（已验证管道可通）或已停止。 */
export type CoreStatus = "normal" | "stopped";

// ---- Command 封装（P4-a：后端返回 not_wired 占位错误） ----

/** 是否运行在 Tauri 外壳内（纯浏览器 `vite dev` 预览时无 IPC bridge）。 */
function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/**
 * invoke 的安全封装：在纯浏览器预览（非 Tauri）下返回友好占位错误，
 * 避免裸 TypeError（Cannot read properties of undefined (reading 'invoke')）。
 */
async function invokeTauri<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    throw { kind: "not_wired", message: "当前运行在 Tauri 外壳之外（纯浏览器预览）；请在 Tauri 应用中运行以连接 core。" };
  }
  return invoke<T>(cmd, args);
}

export const kernel = {
  connect(intent: ConnectIntent): Promise<OperationReply> {
    return invokeTauri<OperationReply>("connect", { intent });
  },
  stop(): Promise<OperationReply> {
    return invokeTauri<OperationReply>("stop");
  },
  snapshot(): Promise<RuntimeSnapshot> {
    return invokeTauri<RuntimeSnapshot>("snapshot");
  },
  coreStatus(): Promise<CoreStatus> {
    return invokeTauri<CoreStatus>("core_status");
  },
  stats(): Promise<RuntimeStats> {
    return invokeTauri<RuntimeStats>("stats");
  },
  logsList(afterSeq: number, limit: number): Promise<LogChunk> {
    return invokeTauri<LogChunk>("logs_list", { afterSeq, limit });
  },
  logsClear(): Promise<LogsClearReply> {
    return invokeTauri<LogsClearReply>("logs_clear");
  },
  configGet(): Promise<ConfigPayload> {
    return invokeTauri<ConfigPayload>("config_get");
  },
  configSet(items: ConfigItem[]): Promise<boolean> {
    return invokeTauri<boolean>("config_set", { items });
  },
  /** 读取 EXV 隧道适配器当前的真实 IPv4 地址；未连接/尚未分配时返回 null。 */
  tunnelAddress(): Promise<string | null> {
    return invokeTauri<string | null>("tunnel_address");
  },
  respondInteraction(interactionId: number[], responsePayload: number[]): Promise<OperationReply> {
    return invokeTauri<OperationReply>("respond_interaction", { interactionId, responsePayload });
  },
  /** 触发一次延迟刷新（T1：写本地标记，engine 探测循环立即 ping；延迟经快照 stats 到达）。 */
  triggerLatencyRefresh(): Promise<void> {
    return invokeTauri<void>("trigger_latency_refresh");
  },
  /** 服务控制（S3/D5）：query 非提权读；install/uninstall/start 经 host runas seam。 */
  serviceControl(action: ServiceControlAction): Promise<ServiceControlReply> {
    return invokeTauri<ServiceControlReply>("service_control", { action });
  },
};

// ---- Event 订阅（P4-b 接真实 WatchEvents/StreamLogs 后生效） ----

export const EVENT_STATUS = "exv://status";
export const EVENT_LOGS = "exv://logs";
export const EVENT_INTERACTION = "exv://interaction";
export const EVENT_STATS = "exv://stats";

export function onStatus(cb: (ev: RuntimeEvent) => void): Promise<UnlistenFn> {
  return listen<RuntimeEvent>(EVENT_STATUS, (e) => cb(e.payload));
}

export function onLogs(cb: (log: LogEvent) => void): Promise<UnlistenFn> {
  return listen<LogEvent>(EVENT_LOGS, (e) => cb(e.payload));
}

/**
 * 统计推送（stats-wire 方案 A 后为 seam：统计随 `exv://status` 的 `snapshot.stats`
 * 到达，前端直接读 `ev.snapshot.stats`；本事件保留供独立高频推送，暂无发射源）。
 */
export function onStats(cb: (stats: RuntimeStats) => void): Promise<UnlistenFn> {
  return listen<RuntimeStats>(EVENT_STATS, (e) => cb(e.payload));
}

/** 命令错误判定：后端占位错误 kind 为 not_wired。 */
export function isNotWired(e: unknown): boolean {
  return (
    typeof e === "object" &&
    e !== null &&
    (e as { kind?: string }).kind === "not_wired"
  );
}
