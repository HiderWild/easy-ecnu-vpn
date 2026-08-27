// 设置页跨页面切换的模块级状态（内存持久化）。
//
// 要求（用户明确）：页面状态要在内存中持久化，切走不遗忘。设置页的草稿、浏览位置
// （活动分区锚点）在用户切回时无缝衔接——不重新加载覆盖草稿、无需额外滚动或重新修改。
// 模块级 ref 在页面组件重挂载（导航切走再切回）后仍保持；仅测试调用 [`resetSettingsState`]
// 或应用进程结束才清除。

import { ref } from "vue";

import type { CoreConfigItem, CoreConfigKey } from "./core-config";

/** 已读取的核心配置项（未知键进「关于与高级」只读区）。 */
export const items = ref<ReadonlyArray<CoreConfigItem>>([]);
/** 编辑中的草稿（含密码——密码不回显，始终以空起始，由用户显式输入新值）。 */
export const drafts = ref<Partial<Record<CoreConfigKey, string>>>({});
/** 加载/保存成功时的基准值（脏追踪用）。 */
export const original = ref<Partial<Record<CoreConfigKey, string>>>({});
/** 字段校验错误（仅非法输入内联显示；保存成功/失败走 toast）。 */
export const feedback = ref<Partial<Record<CoreConfigKey, string>>>({});
export const loading = ref(false);
export const loadError = ref<string | null>(null);
export const saving = ref(false);
/** 当前浏览分区锚点（重挂载时据此恢复滚动位置）。 */
export const activeSection = ref("connection");
/** 本会话是否已成功加载过：重挂载时不重新读取，保留草稿与浏览位置。 */
export const loadedOnce = ref(false);

/** 测试重置（生产路径不调用）。 */
export function resetSettingsState(): void {
  items.value = [];
  drafts.value = {};
  original.value = {};
  feedback.value = {};
  loading.value = false;
  loadError.value = null;
  saving.value = false;
  activeSection.value = "connection";
  loadedOnce.value = false;
}
