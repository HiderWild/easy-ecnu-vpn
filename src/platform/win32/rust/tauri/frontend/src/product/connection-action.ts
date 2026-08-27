import type { ProductUiState } from "./types";

export type ProductConnectionActionKind = "connect" | "stop" | "none";

export type ProductConnectionActionLabel = "连接" | "取消" | "断开" | "重试" | "处理中";

export interface ProductConnectionAction {
  kind: ProductConnectionActionKind;
  label: ProductConnectionActionLabel;
  enabled: boolean;
}

/** 产品动作的唯一决策源；页面只消费 kind 和 label，不根据状态自行猜测。 */
export function connectionActionFor(ui: ProductUiState): ProductConnectionAction {
  if (ui.status === "failed") {
    // failed_clean / failed_dirty 均可重试：点击重连会清除错误并重置状态机（status-map
    // 盲清修复规则1）。"blocking / 需要处理"语义由页面横幅与标题呈现，**不禁用按钮**——
    // 禁用会制造无恢复路径的死锁（按钮永远停在「需要处理」，无法回到可连接态）。
    return { kind: "connect", label: "重试", enabled: true };
  }
  if (ui.connectEnabled) {
    return { kind: "connect", label: "连接", enabled: true };
  }
  if (ui.stopEnabled) {
    return {
      kind: "stop",
      label: ui.status === "connected" ? "断开" : "取消",
      enabled: true,
    };
  }
  return { kind: "none", label: "处理中", enabled: false };
}
