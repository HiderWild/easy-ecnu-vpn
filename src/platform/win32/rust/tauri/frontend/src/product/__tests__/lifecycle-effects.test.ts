import { describe, expect, it } from "vitest";

import {
  computeLifecycleEffects,
  shouldAutoConnectOnLaunch,
  CONNECTED_BODY,
  CONNECTED_TITLE,
  DISCONNECTED_BODY,
  DISCONNECTED_TITLE,
} from "../lifecycle-effects";
import { DEFAULT_UI_PREFERENCES } from "../ui-prefs";

const prefsOn = (): ReturnType<typeof fullPrefs> => ({
  ...DEFAULT_UI_PREFERENCES,
  minimize_to_tray_on_connect: true,
  connect_notify: true,
  disconnect_notify: true,
});
function fullPrefs() {
  return { ...DEFAULT_UI_PREFERENCES };
}

describe("computeLifecycleEffects · 通知默认值", () => {
  it("四个通知键默认值：connect/disconnect/reconnect 关，前台抑制开", () => {
    expect(DEFAULT_UI_PREFERENCES.connect_notify).toBe(false);
    expect(DEFAULT_UI_PREFERENCES.disconnect_notify).toBe(false);
    expect(DEFAULT_UI_PREFERENCES.reconnect_notify).toBe(false);
    expect(DEFAULT_UI_PREFERENCES.suppress_notify_when_foreground).toBe(true);
  });
});

describe("computeLifecycleEffects · 分事件触发", () => {
  it("first snapshot connected emits nothing (startup debounce)", () => {
    expect(computeLifecycleEffects(null, "connected", prefsOn())).toEqual([]);
  });

  it("idle → connected with both prefs on hides window and notifies", () => {
    expect(computeLifecycleEffects("idle", "connected", prefsOn())).toEqual([
      { kind: "hide-window" },
      { kind: "tray-notify", title: CONNECTED_TITLE, body: CONNECTED_BODY },
    ]);
  });

  it("prefs off → no effects on connect or disconnect", () => {
    const defaults = fullPrefs();
    expect(computeLifecycleEffects("idle", "connected", defaults)).toEqual([]);
    expect(computeLifecycleEffects("connected", "idle", defaults)).toEqual([]);
  });

  it("connected → failed notifies disconnection without touching the window", () => {
    expect(computeLifecycleEffects("connected", "failed", prefsOn())).toEqual([
      { kind: "tray-notify", title: DISCONNECTED_TITLE, body: DISCONNECTED_BODY },
    ]);
  });

  it("connecting intermediate transitions emit nothing", () => {
    const p = prefsOn();
    expect(computeLifecycleEffects("idle", "connecting", p)).toEqual([]);
    expect(computeLifecycleEffects("connecting", "awaiting", p)).toEqual([]);
    // 已连接内部不重触发。
    expect(computeLifecycleEffects("connected", "connected", p)).toEqual([]);
  });

  it("connect notification is controlled by connect_notify alone", () => {
    const prefs = { ...fullPrefs(), connect_notify: true, disconnect_notify: false };
    expect(computeLifecycleEffects("idle", "connected", prefs)).toEqual([
      { kind: "tray-notify", title: CONNECTED_TITLE, body: CONNECTED_BODY },
    ]);
    // 断开仍由 disconnect_notify 单独控制。
    expect(computeLifecycleEffects("connected", "idle", prefs)).toEqual([]);
  });

  it("disconnect notification is controlled by disconnect_notify alone", () => {
    const prefs = { ...fullPrefs(), connect_notify: false, disconnect_notify: true };
    expect(computeLifecycleEffects("idle", "connected", prefs)).toEqual([]);
    expect(computeLifecycleEffects("connected", "idle", prefs)).toEqual([
      { kind: "tray-notify", title: DISCONNECTED_TITLE, body: DISCONNECTED_BODY },
    ]);
  });

  it("legacy connection_state_notifications no longer drives notifications", () => {
    const prefs = { ...fullPrefs(), connection_state_notifications: true };
    expect(computeLifecycleEffects("idle", "connected", prefs)).toEqual([]);
    expect(computeLifecycleEffects("connected", "idle", prefs)).toEqual([]);
  });
});

describe("computeLifecycleEffects · 前台抑制", () => {
  it("缩托盘边界（R6）：前台 + 抑制开 + 连接后缩托盘 → 仍弹连接通知，断开通知仍抑制", () => {
    // 组合：connect_notify + suppress_notify_when_foreground + minimize_to_tray_on_connect
    // + foreground=true → 应产出 tray-notify（而非被抑制）+ hide-window。
    const prefs = prefsOn();
    expect(computeLifecycleEffects("idle", "connected", prefs, { foreground: true })).toEqual([
      { kind: "hide-window" },
      { kind: "tray-notify", title: CONNECTED_TITLE, body: CONNECTED_BODY },
    ]);
    // 断开不缩托盘 → 前台抑制仍然生效。
    expect(computeLifecycleEffects("connected", "idle", prefs, { foreground: true })).toEqual([]);
  });

  it("不缩托盘 + 前台 + 抑制开 → 连接/断开通知均被抑制", () => {
    const prefs = { ...fullPrefs(), connect_notify: true, disconnect_notify: true };
    expect(computeLifecycleEffects("idle", "connected", prefs, { foreground: true })).toEqual([]);
    expect(computeLifecycleEffects("connected", "idle", prefs, { foreground: true })).toEqual([]);
  });

  it("抑制开关关闭时，前台仍发送通知", () => {
    const prefs = {
      ...fullPrefs(),
      connect_notify: true,
      disconnect_notify: true,
      suppress_notify_when_foreground: false,
    };
    expect(computeLifecycleEffects("idle", "connected", prefs, { foreground: true })).toEqual([
      { kind: "tray-notify", title: CONNECTED_TITLE, body: CONNECTED_BODY },
    ]);
    expect(computeLifecycleEffects("connected", "idle", prefs, { foreground: true })).toEqual([
      { kind: "tray-notify", title: DISCONNECTED_TITLE, body: DISCONNECTED_BODY },
    ]);
  });

  it("缺省上下文（不在前台）不触发抑制", () => {
    const prefs = { ...fullPrefs(), connect_notify: true };
    expect(computeLifecycleEffects("idle", "connected", prefs)).toEqual([
      { kind: "tray-notify", title: CONNECTED_TITLE, body: CONNECTED_BODY },
    ]);
  });
});

describe("shouldAutoConnectOnLaunch", () => {
  it("auto-connects only on first idle snapshot with pref on", () => {
    const prefs = { ...fullPrefs(), auto_connect_on_launch: true };
    expect(shouldAutoConnectOnLaunch(true, "idle", prefs)).toBe(true);
    expect(shouldAutoConnectOnLaunch(false, "idle", prefs)).toBe(false);
    expect(shouldAutoConnectOnLaunch(true, "connecting", prefs)).toBe(false);
    expect(shouldAutoConnectOnLaunch(true, "connected", prefs)).toBe(false);
  });

  it("pref off never auto-connects", () => {
    expect(shouldAutoConnectOnLaunch(true, "idle", fullPrefs())).toBe(false);
  });
});
