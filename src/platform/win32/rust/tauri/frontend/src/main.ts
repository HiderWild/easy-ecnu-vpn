import { createApp, watch } from "vue";
import App from "./App.vue";
import {
  APPEARANCE_KEY,
  createAppearance,
  createBrowserSafeAppearanceStorage,
} from "./product/appearance";
import { CORE_CONFIG_GATEWAY_KEY } from "./product/core-config";
import { computeLifecycleEffects, shouldAutoConnectOnLaunch } from "./product/lifecycle-effects";
import { LOGS_GATEWAY_KEY } from "./product/logs";
import { createMockCoreConfigGateway, createMockLogsGateway } from "./product/mock-page-data";
import { createMockRuntime, selectRuntimeSource } from "./product/mock-runtime";
import { createProductRuntime, PRODUCT_RUNTIME_KEY } from "./product/runtime";
import {
  loadUiPreferences,
  provideUiPrefsGateway,
  createTauriUiPrefsGateway,
  uiPreferencesState,
} from "./product/ui-prefs";
import type { ProductStatus } from "./product/types";
import { createWindowChromePort, WINDOW_CHROME_PORT_KEY } from "./product/window-chrome";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/motion.css";
import "./styles/ui-first-shell.css";

const appearance = createAppearance(createBrowserSafeAppearanceStorage(() => window.localStorage));
appearance.applyDocument(document.documentElement);
const chrome = createWindowChromePort();
const source = selectRuntimeSource(import.meta.env.DEV, window.location.search);
const runtime = source === "mock" ? createMockRuntime() : createProductRuntime();
const app = createApp(App);

app.provide(PRODUCT_RUNTIME_KEY, runtime);
app.provide(APPEARANCE_KEY, appearance);
app.provide(WINDOW_CHROME_PORT_KEY, chrome);
if (source === "mock") {
  app.provide(CORE_CONFIG_GATEWAY_KEY, createMockCoreConfigGateway());
  app.provide(LOGS_GATEWAY_KEY, createMockLogsGateway());
}
try {
  await chrome.setMode(appearance.state.value.mode);
} catch (error) {
  console.error("窗口模式初始化失败", error);
  appearance.setMode("advanced");
}

// 前端自有设置：启动即加载（Tauri 外壳内走真实网关；预览环境保持默认值）。
if (source !== "mock") {
  provideUiPrefsGateway(createTauriUiPrefsGateway());
}
await loadUiPreferences();

// 连接过渡效果分发：状态流 → hide-window / tray-notify / 启动自动连接。
let previousStatus: ProductStatus | null = null;
watch(
  runtime.state,
  (productState) => {
    const prefs = uiPreferencesState().value;
    const nextStatus = productState.status;
    const prevStatus = previousStatus;
    const isFirstSnapshot = prevStatus === null;

    // 前台状态异步探测后分发效果；等待期间状态再次变化则由后续回调接管（丢弃本次，避免错序）。
    void (async () => {
      const foreground = await isWindowForeground();
      if (previousStatus !== prevStatus) return;

      for (const effect of computeLifecycleEffects(prevStatus, nextStatus, prefs, { foreground })) {
        if (effect.kind === "hide-window") {
          void chrome.setVisible(false).catch((error: unknown) => {
            console.error("隐藏窗口失败", error);
          });
        } else if (effect.kind === "tray-notify") {
          void invokeTrayNotify(effect.title, effect.body);
        }
      }

      previousStatus = nextStatus;
    })();

    if (shouldAutoConnectOnLaunch(isFirstSnapshot, nextStatus, prefs)) {
      void runtime.connect();
    }
  },
  { immediate: true },
);

/** 主窗口是否在前台（聚焦）：Tauri 外壳用 getCurrentWindow().isFocused()；
 * mock/浏览器环境回退 false（不抑制）；探测失败也按「不在前台」处理（不阻断通知）。 */
async function isWindowForeground(): Promise<boolean> {
  if (source === "mock" || !("__TAURI_INTERNALS__" in window)) return false;
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    return await getCurrentWindow().isFocused();
  } catch (error) {
    console.error("窗口前台状态检测失败", error);
    return false;
  }
}

async function invokeTrayNotify(title: string, body: string): Promise<void> {
  if (source === "mock" || !("__TAURI_INTERNALS__" in window)) return;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("tray_notify", { title, body });
  } catch (error) {
    console.error("托盘通知失败", error);
  }
}

app.mount("#app");

if (source === "mock") {
  const badge = document.createElement("div");
  badge.textContent = "模拟数据";
  badge.setAttribute("role", "status");
  badge.style.cssText = [
    "position:fixed",
    "right:12px",
    "bottom:12px",
    "z-index:2147483647",
    "pointer-events:none",
    "padding:4px 8px",
    "border:1px solid currentColor",
    "border-radius:999px",
    "background:rgba(255,255,255,.9)",
    "color:#4b5563",
    "font:12px/1.2 system-ui,sans-serif",
  ].join(";");
  document.body.append(badge);
}

if (source === "mock" || "__TAURI_INTERNALS__" in window) {
  void runtime.start().catch((error: unknown) => {
    console.error("产品运行时初始化失败", error);
  });
}

window.addEventListener("beforeunload", () => runtime.dispose(), { once: true });
