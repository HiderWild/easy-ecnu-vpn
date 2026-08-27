import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_UI_PREFERENCES,
  editUiPreference,
  normalizeUiPreferences,
  provideUiPrefsGateway,
  resetUiPrefsState,
  loadUiPreferences,
  uiPrefsDirty,
  uiPrefsDraft,
  uiPreferencesState,
  UI_PREF_KEYS,
  updateUiPreferences,
  type UiPrefsGateway,
} from "../ui-prefs";
import { clearToasts } from "../../lib/toast";

function memoryGateway(
  store: Record<string, unknown> = {},
): UiPrefsGateway & { set: ReturnType<typeof vi.fn>; setAutostart: ReturnType<typeof vi.fn> } {
  return {
    get: vi.fn(async () => ({ ...store })),
    set: vi.fn(async (patch) => {
      Object.assign(store, patch);
      return { ...patch };
    }),
    setAutostart: vi.fn(async (enabled) => {
      store.__autostart = enabled;
      return { ok: true };
    }),
  };
}

describe("normalizeUiPreferences", () => {
  it("falls back to defaults on missing or invalid values", () => {
    const merged = normalizeUiPreferences({
      close_preference: "minimize" as never,
      launch_at_login: "yes" as never,
      silent_startup: true,
    });
    expect(merged).toEqual({
      ...DEFAULT_UI_PREFERENCES,
      silent_startup: true,
    });
  });

  it("returns full defaults for null/undefined", () => {
    expect(normalizeUiPreferences(null)).toEqual(DEFAULT_UI_PREFERENCES);
    expect(normalizeUiPreferences(undefined)).toEqual(DEFAULT_UI_PREFERENCES);
  });
});

describe("ui prefs draft + save flow", () => {
  beforeEach(() => {
    resetUiPrefsState();
    clearToasts();
  });

  it("loads effective values once and keeps defaults when unavailable", async () => {
    const gateway = memoryGateway({ close_preference: "quit", silent_startup: true });
    provideUiPrefsGateway(gateway);
    await loadUiPreferences();
    await loadUiPreferences();
    expect(gateway.get).toHaveBeenCalledTimes(1);
    expect(uiPreferencesState().value.close_preference).toBe("quit");

    // 后端不可用：保持默认值。
    resetUiPrefsState();
    provideUiPrefsGateway({
      get: vi.fn(async () => {
        throw new Error("no tauri");
      }),
      set: vi.fn(),
      setAutostart: vi.fn(),
    });
    await loadUiPreferences();
    expect(uiPreferencesState().value).toEqual(DEFAULT_UI_PREFERENCES);
  });

  it("edits go to draft only; not effective until save", async () => {
    const gateway = memoryGateway();
    provideUiPrefsGateway(gateway);
    await loadUiPreferences();

    editUiPreference("silent_startup", true);
    // 草稿可见，生效值未变。
    expect(uiPrefsDraft.value.silent_startup).toBe(true);
    expect(uiPreferencesState().value.silent_startup).toBe(false);
    expect(uiPrefsDirty.value).toBe(true);
    expect(gateway.set).not.toHaveBeenCalled();

    const ok = await updateUiPreferences();
    expect(ok).toBe(true);
    expect(uiPreferencesState().value.silent_startup).toBe(true);
    expect(uiPrefsDirty.value).toBe(false);
    expect(gateway.set).toHaveBeenCalledWith({ silent_startup: true });
  });

  it("editing back to the original value clears dirtiness for that key", async () => {
    const gateway = memoryGateway();
    provideUiPrefsGateway(gateway);
    await loadUiPreferences();

    editUiPreference("silent_startup", true);
    expect(uiPrefsDirty.value).toBe(true);
    editUiPreference("silent_startup", false);
    expect(uiPrefsDirty.value).toBe(false);

    await updateUiPreferences(); // no-op
    expect(gateway.set).not.toHaveBeenCalled();
  });

  it("launch_at_login drives registry first; registry failure rolls everything back", async () => {
    const gateway = memoryGateway();
    provideUiPrefsGateway(gateway);
    await loadUiPreferences();

    editUiPreference("launch_at_login", true);
    editUiPreference("silent_startup", true);
    const ok = await updateUiPreferences();
    expect(ok).toBe(true);
    // 注册表先写（真相源），偏好文件后落（显示态）。
    expect(gateway.setAutostart.mock.invocationCallOrder[0]).toBeLessThan(
      gateway.set.mock.invocationCallOrder[0],
    );

    // 注册表失败：全部回滚（含其他键），状态保持旧值。
    resetUiPrefsState();
    const failing = memoryGateway();
    failing.setAutostart.mockResolvedValueOnce({ ok: false, message: "denied" });
    provideUiPrefsGateway(failing);
    await loadUiPreferences();

    editUiPreference("launch_at_login", true);
    editUiPreference("disconnect_notify", true);
    const rolledBack = await updateUiPreferences();
    expect(rolledBack).toBe(false);
    expect(uiPreferencesState().value.launch_at_login).toBe(false);
    expect(uiPreferencesState().value.disconnect_notify).toBe(false);
  });

  it("close_preference accepts only known enum values from gateway", async () => {
    const gateway = memoryGateway({ close_preference: "bogus" });
    provideUiPrefsGateway(gateway);

    await loadUiPreferences();
    expect(uiPreferencesState().value.close_preference).toBe("smart");
  });
});

describe("通知拆分键", () => {
  it("四个通知键默认值正确（前台抑制默认开）", () => {
    expect(DEFAULT_UI_PREFERENCES.connect_notify).toBe(false);
    expect(DEFAULT_UI_PREFERENCES.disconnect_notify).toBe(false);
    expect(DEFAULT_UI_PREFERENCES.reconnect_notify).toBe(false);
    expect(DEFAULT_UI_PREFERENCES.suppress_notify_when_foreground).toBe(true);
  });

  it("normalize 读取四个新键并回落默认", () => {
    const merged = normalizeUiPreferences({
      connect_notify: true,
      disconnect_notify: true,
      reconnect_notify: true,
      suppress_notify_when_foreground: false,
    });
    expect(merged.connect_notify).toBe(true);
    expect(merged.disconnect_notify).toBe(true);
    expect(merged.reconnect_notify).toBe(true);
    expect(merged.suppress_notify_when_foreground).toBe(false);
  });

  it("旧 connection_state_notifications 仅保留存储兼容（可读、不再可编辑）", () => {
    // 可读：旧文件值仍进状态（保留兼容）。
    const merged = normalizeUiPreferences({ connection_state_notifications: true });
    expect(merged.connection_state_notifications).toBe(true);
    // 不再可编辑：不在可保存键集合内（设置页不再渲染旧开关）。
    expect(UI_PREF_KEYS).not.toContain("connection_state_notifications");
    expect(UI_PREF_KEYS).toEqual(
      expect.arrayContaining([
        "connect_notify",
        "disconnect_notify",
        "reconnect_notify",
        "suppress_notify_when_foreground",
      ]),
    );
  });

  it("四个通知键经网关保存并生效", async () => {
    const gateway = memoryGateway();
    provideUiPrefsGateway(gateway);
    await loadUiPreferences();

    editUiPreference("connect_notify", true);
    editUiPreference("disconnect_notify", true);
    editUiPreference("reconnect_notify", true);
    editUiPreference("suppress_notify_when_foreground", false);
    const ok = await updateUiPreferences();
    expect(ok).toBe(true);
    expect(uiPreferencesState().value.connect_notify).toBe(true);
    expect(uiPreferencesState().value.disconnect_notify).toBe(true);
    expect(uiPreferencesState().value.reconnect_notify).toBe(true);
    expect(uiPreferencesState().value.suppress_notify_when_foreground).toBe(false);
    expect(gateway.set).toHaveBeenCalledWith(
      expect.objectContaining({
        connect_notify: true,
        disconnect_notify: true,
        reconnect_notify: true,
        suppress_notify_when_foreground: false,
      }),
    );
  });
});
