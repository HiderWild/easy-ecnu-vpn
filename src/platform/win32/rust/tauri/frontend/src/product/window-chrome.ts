import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
import type { InjectionKey } from "vue";

export type WindowMode = "advanced" | "minimal";
export type NativeWindowControl = "minimize" | "maximize" | "close";
export interface NativeWindowControlState {
  control: NativeWindowControl | null;
  pressed: boolean;
}
export type WindowChromeEventListener = (event: { payload: unknown }) => void;
export type WindowChromeListen = (
  event: string,
  listener: WindowChromeEventListener,
) => Promise<() => void>;

export interface WindowChromePort {
  setMode(mode: WindowMode): Promise<void>;
  control(control: NativeWindowControl): Promise<void>;
  /** 窗口显隐原语（连接后最小化到托盘 / 托盘唤出）；纯显隐，不携带关闭语义。 */
  setVisible(visible: boolean): Promise<void>;
  subscribeControlState(listener: (state: NativeWindowControlState) => void): Promise<() => void>;
}
export const WINDOW_CHROME_PORT_KEY: InjectionKey<WindowChromePort> = Symbol("exv.product.window-chrome");
export interface WindowChromeOptions {
  browserPreview?: boolean;
  invoke?: (
    command: string,
    args: { mode: WindowMode } | { control: NativeWindowControl } | { visible: boolean },
  ) => Promise<unknown>;
  listen?: WindowChromeListen;
}

function isNativeWindowControl(value: unknown): value is NativeWindowControl {
  return value === "minimize" || value === "maximize" || value === "close";
}

function parseControlState(payload: unknown): NativeWindowControlState {
  if (typeof payload !== "object" || payload === null) {
    return { control: null, pressed: false };
  }
  const raw = payload as { control?: unknown; pressed?: unknown };
  return {
    control: isNativeWindowControl(raw.control) ? raw.control : null,
    pressed: raw.pressed === true,
  };
}

export function createWindowChromePort(options: WindowChromeOptions = {}): WindowChromePort {
  const browserPreview = options.browserPreview ?? (options.invoke === undefined && !(typeof window !== "undefined" && "__TAURI_INTERNALS__" in window));
  const invoke = options.invoke ?? ((command, args) => tauriInvoke(command, args));
  const listen = options.listen ?? ((event, listener) => tauriListen<unknown>(event, listener));
  return {
    async setMode(mode) {
      if (browserPreview) return;
      await invoke("window_chrome_set_mode", { mode });
    },
    async control(control) {
      if (browserPreview) return;
      await invoke("window_chrome_control", { control });
    },
    async setVisible(visible) {
      if (browserPreview) return;
      await invoke("window_set_visible", { visible });
    },
    async subscribeControlState(listener) {
      if (browserPreview) return () => undefined;
      return listen("window-control-state", (event) => listener(parseControlState(event.payload)));
    },
  };
}
