// 前端自有设置（UI preferences）：纯 UI 行为偏好的状态层。
//
// 边界切割（与 app/src/ui_prefs.rs 头注释同源）：
//   * core 配置（server/username/…）走 core-config.ts 的 config_get/set——本模块绝不触碰；
//   * 本模块的键是纯前端行为偏好，存 `%LOCALAPPDATA%\EXV\profile\default\ui-preferences.json`
//     （字段名照抄 C++ 宿主偏好契约，升级时 schema 同源；Rust 侧负责持久化与 legacy 导入）。
//
// 保存模型（用户拍板 2026-08-23）：除外观个性化即时生效外，偏好修改先进草稿；
// 「保存」时统一解析脏修改并分流应用（注册表 / 偏好文件）。`updateUiPreferences`
// 是保存动作的执行器；页面编辑只写 `draft`。

import { computed, ref } from "vue";

import { pushToast } from "../lib/toast";

export type ClosePreference = "smart" | "tray" | "quit";

export interface UiPreferences {
  /** 关闭按钮行为："smart"（误关保护宽限）| "tray" | "quit"。 */
  close_preference: ClosePreference;
  /** 连接成功后自动隐藏窗口到托盘。 */
  minimize_to_tray_on_connect: boolean;
  /** 开机自动运行。 */
  launch_at_login: boolean;
  /** 启动静默：所有启动方式都不弹窗，仅托盘驻留。 */
  silent_startup: boolean;
  /** 遗留键（存储兼容）：旧版「连接状态通知」单开关。新版本不再渲染/消费，
   * 仅保留读写以兼容旧偏好文件；其 true 不再驱动任何通知（由下方分事件键接管）。 */
  connection_state_notifications: boolean;
  /** 建立连接时发送通知。 */
  connect_notify: boolean;
  /** 断开连接时发送通知。 */
  disconnect_notify: boolean;
  /** 触发重连时发送通知（C5 自动重连落地前仅开关+文案，效果待接线）。 */
  reconnect_notify: boolean;
  /** 窗口在前台（聚焦）时抑制所有连接类通知；优先级最高。 */
  suppress_notify_when_foreground: boolean;
  /** 应用启动且空闲时自动发起连接。 */
  auto_connect_on_launch: boolean;
}

/** 全部可保存键（页面据此渲染控件；旧 connection_state_notifications 不再渲染/可编辑）。 */
export const UI_PREF_KEYS = [
  "close_preference",
  "minimize_to_tray_on_connect",
  "launch_at_login",
  "silent_startup",
  "connect_notify",
  "disconnect_notify",
  "reconnect_notify",
  "suppress_notify_when_foreground",
  "auto_connect_on_launch",
] as const;

export type UiPrefKey = (typeof UI_PREF_KEYS)[number];

export const CLOSE_PREFERENCE_VALUES: readonly ClosePreference[] = ["smart", "tray", "quit"];

export const DEFAULT_UI_PREFERENCES: UiPreferences = {
  close_preference: "smart",
  minimize_to_tray_on_connect: false,
  launch_at_login: false,
  silent_startup: false,
  connection_state_notifications: false,
  connect_notify: false,
  disconnect_notify: false,
  reconnect_notify: false,
  suppress_notify_when_foreground: true,
  auto_connect_on_launch: false,
};

export const CLOSE_PREFERENCE_LABELS: Record<ClosePreference, string> = {
  smart: "智能判断最小化与退出",
  tray: "最小化到托盘",
  quit: "直接退出",
};

export type UiPreferencesPatch = Partial<UiPreferences>;

/** 后端 Command 的返回/入参形状：字段可缺省（读 = 有效值视图；写 = 补丁）。 */
export type UiPreferencesWire = UiPreferencesPatch;

export interface UiPrefsGateway {
  get(): Promise<UiPreferencesWire>;
  set(patch: UiPreferencesPatch): Promise<UiPreferencesWire>;
  /** 设置开机自启（注册表执行层）；返回 ok + message。 */
  setAutostart(enabled: boolean): Promise<{ ok: boolean; message?: string }>;
}

/** 校验 wire 值并回落默认（坏值不进状态）。 */
export function normalizeUiPreferences(raw: UiPreferencesWire | null | undefined): UiPreferences {
  const merged: UiPreferences = { ...DEFAULT_UI_PREFERENCES };
  if (!raw || typeof raw !== "object") return merged;

  if (
    typeof raw.close_preference === "string" &&
    (CLOSE_PREFERENCE_VALUES as readonly string[]).includes(raw.close_preference)
  ) {
    merged.close_preference = raw.close_preference;
  }
  for (const key of [
    "minimize_to_tray_on_connect",
    "launch_at_login",
    "silent_startup",
    "connection_state_notifications",
    "connect_notify",
    "disconnect_notify",
    "reconnect_notify",
    "suppress_notify_when_foreground",
    "auto_connect_on_launch",
  ] as const) {
    const value = raw[key];
    if (typeof value === "boolean") merged[key] = value;
  }
  return merged;
}

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

async function invokeCommand<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    throw new Error("ui prefs 仅在 Tauri 外壳内可用");
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

/** 生产网关：走 Tauri Command（ui_prefs.rs / autostart.rs）。 */
export function createTauriUiPrefsGateway(): UiPrefsGateway {
  return {
    get() {
      return invokeCommand<UiPreferencesWire>("ui_prefs_get");
    },
    set(patch) {
      return invokeCommand<UiPreferencesWire>("ui_prefs_set", { patch });
    },
    async setAutostart(enabled) {
      return invokeCommand<{ ok: boolean; message?: string }>("autostart_set", { enabled });
    },
  };
}

// ---- 模块级单例：已生效值 + 草稿 ----

const state = ref<UiPreferences>({ ...DEFAULT_UI_PREFERENCES });
const draft = ref<Partial<UiPreferences>>({});
let gateway: UiPrefsGateway | null = null;
let loadedOnce = false;
let loadPromise: Promise<void> | null = null;

/** 草稿视图（页面控件读这里；缺键回落已生效值）。 */
export const uiPrefsDraft = computed<UiPreferences>(() => ({ ...state.value, ...draft.value }));

/** 是否存在未保存的偏好修改。 */
export const uiPrefsDirty = computed(() => Object.keys(draft.value).length > 0);

/** 测试重置（生产路径不调用）。 */
export function resetUiPrefsState(): void {
  state.value = { ...DEFAULT_UI_PREFERENCES };
  draft.value = {};
  gateway = null;
  loadedOnce = false;
  loadPromise = null;
}

/** 注入网关（测试注入内存实现；生产在 main.ts 调用一次装真实网关）。
 * 换网关后允许重新 load（新网关的存储才是真相源）。 */
export function provideUiPrefsGateway(impl: UiPrefsGateway): void {
  gateway = impl;
  loadedOnce = false;
  loadPromise = null;
}

/**
 * 加载一次有效偏好（重复调用复用在途/已完成的结果）。
 * Tauri 外壳之外（纯浏览器预览）保持默认值，不视为错误。
 * 加载会丢弃草稿（存储是真相源；仅在启动加载场景发生）。
 */
export async function loadUiPreferences(): Promise<void> {
  if (loadedOnce) return;
  if (loadPromise !== null) return loadPromise;

  loadPromise = (async () => {
    const impl = gateway ?? createTauriUiPrefsGateway();
    try {
      const raw = await impl.get();
      state.value = normalizeUiPreferences(raw);
      draft.value = {};
      loadedOnce = true;
    } catch {
      // 外壳之外 / 后端不可用：保持默认值（诚实降级，不阻断 UI）。
    }
  })();

  try {
    await loadPromise;
  } finally {
    loadPromise = null;
  }
}

/** 编辑草稿（页面控件调用；不落盘、不生效）。 */
export function editUiPreference<K extends UiPrefKey>(key: K, value: UiPreferences[K]): void {
  if (value === state.value[key]) {
    // 改回原值 = 该键不再脏。
    const next = { ...draft.value };
    delete next[key];
    draft.value = next;
    return;
  }
  draft.value = { ...draft.value, [key]: value };
}

function effectiveImpl(): UiPrefsGateway {
  return gateway ?? createTauriUiPrefsGateway();
}

/**
 * 保存动作执行器：解析脏修改并分流应用。
 *
 * 分流规则：
 *   * `launch_at_login` → 先写注册表（执行真相源），再持久化偏好文件（显示态）；
 *   * 其余键 → 直接持久化偏好文件（UI 进程启动时读取生效）。
 *
 * 任一分流失败：回滚全部（含已成功的部分——注册表写回原值）、toast 报错、返回 false。
 * 成功：清空草稿、toast 确认。
 */
export async function updateUiPreferences(): Promise<boolean> {
  const patch = { ...draft.value };
  if (Object.keys(patch).length === 0) return true;
  const previous = state.value;
  const nextFull = normalizeUiPreferences({ ...previous, ...patch });

  try {
    const impl = effectiveImpl();

    // 分流一：注册表（先执行后记录；失败即整体失败）。
    if (patch.launch_at_login !== undefined && patch.launch_at_login !== previous.launch_at_login) {
      const result = await impl.setAutostart(patch.launch_at_login);
      if (!result.ok) throw new Error(result.message ?? "autostart rejected");
    }

    // 分流二：偏好文件。
    await impl.set(patch);

    state.value = normalizeUiPreferences({ ...state.value, ...patch });
    draft.value = {};
    pushToast("设置已保存。", "success");
    return true;
  } catch {
    // 注册表可能已写新值：回写到旧值（best effort）。
    if (
      patch.launch_at_login !== undefined &&
      patch.launch_at_login !== previous.launch_at_login
    ) {
      try {
        await effectiveImpl().setAutostart(previous.launch_at_login);
      } catch {
        // 回滚失败仅记录；状态仍按未保存处理。
      }
    }
    void nextFull; // 仅用于类型完整性；状态保持 previous。
    pushToast("设置保存失败。", "error");
    return false;
  }
}

/** 只读视图（运行时效果消费 lifecycle-effects 等）。 */
export function uiPreferencesState() {
  return state;
}
