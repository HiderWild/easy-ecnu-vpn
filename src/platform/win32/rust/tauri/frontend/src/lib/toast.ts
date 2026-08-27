// 全局一次性状态提醒（右下角彩色圆角浮层）。
//
// 产品 UI 呈现规则（用户明确）：**大段/详细信息走模态弹窗；小的一次性状态走右下角
// 彩色圆角 toast**（同 C++ webview 行为）。本模块是 toast 的单一来源——页面不自行
// 渲染内联状态块。
//
// 复用评估（按「先复用、再实现」原则，2026-08-22）：
//   * 成熟方案：vue3-toastify / vue-toastification（MIT、活跃维护）确实解决同一问题。
//   * 不采用的理由（落在原则的「小能力豁免」）：本项目运行时刻意只有 2 个依赖
//     （@tauri-apps/api + vue）、无 UI 框架、全站手搓组件；toast 是 ~60 行的极小
//     能力，引入完整 toast 库（自带样式系统/SSR 支持/完整 API 面）属于「为一个很小
//     的能力引入不必要的大系统」。模态沿用项目自身已确立的手搓 modal 模式
//     （ServiceConnectFailureModal）。
//   * 采用本地实现（行为经 vitest 锁定）：lib/toast.ts（状态）+ components/ToastStack.vue
//     （渲染，右下角彩色圆角，自动消除/点击关闭）。

import { reactive } from "vue";

export type ToastKind = "info" | "success" | "warning" | "error";

export interface ToastItem {
  id: number;
  message: string;
  kind: ToastKind;
}

/** 全局 toast 队列（reactive；`ToastStack.vue` 挂载于 App 根渲染）。 */
const toasts = reactive<ToastItem[]>([]);
let nextId = 1;

/** 一次性状态提醒默认停留时长。 */
const TOAST_DURATION_MS = 4000;

/** 弹一条一次性状态提醒（自动消除；点击可提前关闭）。 */
export function pushToast(message: string, kind: ToastKind = "info"): void {
  const id = nextId++;
  toasts.push({ id, message, kind });
  window.setTimeout(() => dismissToast(id), TOAST_DURATION_MS);
}

/** 手动消除一条 toast（点击 / 超时）。 */
export function dismissToast(id: number): void {
  const index = toasts.findIndex((item) => item.id === id);
  if (index >= 0) {
    toasts.splice(index, 1);
  }
}

/** 清空全部 toast（测试重置用；生产路径不调用）。 */
export function clearToasts(): void {
  toasts.splice(0, toasts.length);
}

/** 连接 ToastStack 组件的只读队列 + 消除句柄。 */
export function useToasts(): { toasts: ToastItem[]; dismiss: (id: number) => void } {
  return { toasts, dismiss: dismissToast };
}
