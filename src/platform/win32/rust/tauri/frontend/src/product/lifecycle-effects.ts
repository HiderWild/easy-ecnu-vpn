// 连接过渡效果（纯函数 + 薄分发）：状态变化 → 窗口/托盘效果。
//
// 效果全部由前端自有设置驱动（ui-prefs），不触碰 core 配置：
//   * 进入 connected：`minimize_to_tray_on_connect` → 隐藏窗口；
//     `connect_notify` → 托盘气泡「已连接」。
//   * 离开 connected（任一非连接态）：`disconnect_notify` → 托盘气泡「已断开」（窗口不动）。
//   * 触发重连（`reconnect_notify` → 「正在重连」）：当前 ProductStatus 无专门重连态
//     （idle/connecting/awaiting/connected/stopping/reconciling/failed），无法感知重连
//     触发事件；开关与文案已在设置页就绪，效果接线待 C5 自动重连落地。
//   * 前台抑制：窗口在前台（聚焦）且 `suppress_notify_when_foreground` 开启时，抑制全部
//     连接类通知（隐藏窗口动作不受影响）。前台状态由调用方（main.ts）判定后作为
//     `NotifyContext` 传入，本函数保持纯函数。
//   * 缩托盘边界（R6）：进入 connected 的本批效果即将缩到托盘（`minimize_to_tray_on_connect`）
//     时，用户看不到 UI，前台抑制视为不命中——仍弹一次连接通知，符合直觉。
//   * 首快照去抖：应用启动即已连接时不发通知（对齐旧 webui 的
//     connectionNotificationState 初始化语义——首见只记录基线）。

import type { ProductStatus } from "./types";
import type { UiPreferences } from "./ui-prefs";

/** 单个过渡效果的执行指令。 */
export type LifecycleEffect =
  | { kind: "hide-window" }
  | { kind: "tray-notify"; title: string; body: string };

export const CONNECTED_TITLE = "EXV 已连接";
export const CONNECTED_BODY = "校园网连接已建立。";
export const DISCONNECTED_TITLE = "EXV 已断开";
export const DISCONNECTED_BODY = "校园网连接已断开。";

function isConnected(status: ProductStatus): boolean {
  return status === "connected";
}

/** 通知上下文（调用方注入的前台状态；纯函数不自行探测窗口）。 */
export interface NotifyContext {
  /** 主窗口当前是否在前台（聚焦）。 */
  foreground: boolean;
}

/** 前台抑制判定：窗口在前台 且 抑制开关开启 → 抑制连接类通知（优先级最高）。 */
function notifyBlocked(prefs: UiPreferences, context: NotifyContext): boolean {
  return context.foreground && prefs.suppress_notify_when_foreground;
}

/**
 * 由前后两个产品状态计算过渡效果（无副作用；分发由接线层完成）。
 *
 * @param prevStatus 前一状态（`null` = 应用启动后的首快照）。
 * @param nextStatus 当前状态。
 * @param prefs 生效中的前端偏好。
 * @param context 通知上下文（前台状态）；缺省按「不在前台」处理（不触发抑制）。
 */
export function computeLifecycleEffects(
  prevStatus: ProductStatus | null,
  nextStatus: ProductStatus,
  prefs: UiPreferences,
  context: NotifyContext = { foreground: false },
): LifecycleEffect[] {
  const effects: LifecycleEffect[] = [];
  const firstSnapshot = prevStatus === null;
  const wasConnected = !firstSnapshot && isConnected(prevStatus);
  const nowConnected = isConnected(nextStatus);

  if (nowConnected && !wasConnected) {
    const willHideWindow = !firstSnapshot && prefs.minimize_to_tray_on_connect;
    if (willHideWindow) {
      effects.push({ kind: "hide-window" });
    }
    // 缩托盘边界（R6）：本批即将隐藏窗口 → 用户看不到 UI → 前台抑制视为不命中，仍弹连接通知。
    const notifyForeground = context.foreground && !willHideWindow;
    if (!firstSnapshot && prefs.connect_notify && !notifyBlocked(prefs, { foreground: notifyForeground })) {
      effects.push({ kind: "tray-notify", title: CONNECTED_TITLE, body: CONNECTED_BODY });
    }
    return effects;
  }

  if (!nowConnected && wasConnected && prefs.disconnect_notify && !notifyBlocked(prefs, context)) {
    effects.push({ kind: "tray-notify", title: DISCONNECTED_TITLE, body: DISCONNECTED_BODY });
  }
  return effects;
}

/**
 * 启动自动连接的门禁判定：首快照空闲 + pref 开启 → 自动发起一次连接。
 * （旧 webui 还检查 remember_password/serviceInstalled；Rust 侧前端拿不到这些
 * 数据口，v1 以 idle 为门禁，失败按常规 failed 态诚实呈现，不静默重试。）
 */
export function shouldAutoConnectOnLaunch(
  isFirstSnapshot: boolean,
  status: ProductStatus,
  prefs: UiPreferences,
): boolean {
  return isFirstSnapshot && status === "idle" && prefs.auto_connect_on_launch;
}
