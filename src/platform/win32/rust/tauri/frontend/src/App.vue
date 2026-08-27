<script setup lang="ts">
import { computed, inject, ref, type Component } from "vue";
import ConnectPage from "./pages/ConnectPage.vue";
import LogsPage from "./pages/LogsPage.vue";
import SettingsPage from "./pages/SettingsPage.vue";
import AboutPage from "./pages/AboutPage.vue";
import ProductWindowFrame from "./components/ProductWindowFrame.vue";
import MinimalConnectionView from "./components/MinimalConnectionView.vue";
import ToastStack from "./components/ToastStack.vue";
import { APPEARANCE_KEY } from "./product/appearance";
import { connectionActionFor } from "./product/connection-action";
import { PRODUCT_RUNTIME_KEY } from "./product/runtime";
import { WINDOW_CHROME_PORT_KEY } from "./product/window-chrome";

type PageKey = "connect" | "logs" | "settings" | "about";

const pages: { key: PageKey; label: string; component: Component }[] = [
  { key: "connect", label: "连接", component: ConnectPage },
  { key: "logs", label: "日志", component: LogsPage },
  { key: "settings", label: "设置", component: SettingsPage },
  { key: "about", label: "关于", component: AboutPage },
];

const current = ref<PageKey>("connect");
const currentComponent = computed(() => pages.find((p) => p.key === current.value)!.component);
const appearance = inject(APPEARANCE_KEY)!;
const chrome = inject(WINDOW_CHROME_PORT_KEY)!;
const runtime = inject(PRODUCT_RUNTIME_KEY)!;
const mode = computed(() => appearance.state.value.mode);
const productState = computed(() => runtime.state.value);
const minimalAction = computed(() => connectionActionFor(productState.value));

async function runMinimalAction(): Promise<void> {
  const action = minimalAction.value;
  if (!action.enabled) return;
  if (action.kind === "connect") await runtime.connect();
  if (action.kind === "stop") await runtime.stop();
}
</script>

<template>
  <ProductWindowFrame :mode="mode" :chrome="chrome" :appearance="appearance" :current-page="current" @navigate="current = $event">
    <MinimalConnectionView
      v-if="mode === 'minimal'"
      :state="productState"
      :action="minimalAction"
      @run="runMinimalAction"
    />
    <main v-else class="content"><component :is="currentComponent" /></main>
  </ProductWindowFrame>
  <ToastStack />
</template>

<style scoped>
.shell {
  display: flex;
  height: 100%;
}
.sidebar {
  width: 180px;
  flex: none;
  background: var(--bg-2);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  padding: 16px 12px;
  gap: 8px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 6px 16px;
}
.brand-mark {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 3px solid var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}
.brand-name {
  font-weight: 700;
  letter-spacing: 0.5px;
}
nav {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
}
.nav-item {
  text-align: left;
  background: transparent;
  border: none;
  border-radius: 6px;
  padding: 9px 10px;
  color: var(--text-dim);
}
.nav-item:hover {
  background: var(--panel);
  color: var(--text);
}
.nav-item.active {
  background: var(--panel);
  color: var(--text);
  border-left: 2px solid var(--accent);
}
.sidebar-foot {
  font-size: 12px;
  padding: 4px 6px;
}
.content {
  flex: 1;
  min-width: 0;
  /* 对齐 C++ 布局：content 是固定可视高容器（h-full + overflow-hidden），不随内容撑高。
     上下内边距取消（只留左右 28px）：设置/日志页不再需要负 margin 爬升，banner 落在
     外层 .product-content 的 24px 上边距处、底部无额外空隙（此前 -48px 爬升导致头部
     被裁剪 + 底边距虚大）。页面内部自行管理滚动。 */
  height: 100%;
  overflow: hidden;
  padding: 0 28px;
}
</style>
