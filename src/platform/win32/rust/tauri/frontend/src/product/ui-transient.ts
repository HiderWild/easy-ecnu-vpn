// 跨页面瞬态 UI 状态（模块级：页面切换重挂载仍保持；仅在新用户动作时重置）。
//
// 背景：认证失败模态在关闭后若存组件内 ref，切到设置页再切回会因 ConnectPage 重新
// 挂载而重置为未关闭 → 模态反复弹出（用户未再点连接也弹）。放模块级让关闭标记在
// 会话内保持，直到下一次连接动作。

import { ref } from "vue";

/** 认证失败模态是否已被用户关闭（新连接动作才重置为 false）。 */
export const authModalDismissed = ref(false);

/** 测试重置（生产路径不调用）。 */
export function resetAuthModalDismissed(): void {
  authModalDismissed.value = false;
}
