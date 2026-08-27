import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import App from "../../App.vue";
import {
  APPEARANCE_KEY,
  createAppearance,
  type AppearanceStorage,
} from "../../product/appearance";
import { CORE_CONFIG_GATEWAY_KEY } from "../../product/core-config";
import { LOGS_GATEWAY_KEY } from "../../product/logs";
import { createMockCoreConfigGateway, createMockLogsGateway } from "../../product/mock-page-data";
import { createMockRuntime } from "../../product/mock-runtime";
import { PRODUCT_RUNTIME_KEY } from "../../product/runtime";
import {
  createWindowChromePort,
  WINDOW_CHROME_PORT_KEY,
} from "../../product/window-chrome";

function memoryStorage(): AppearanceStorage {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => void values.set(key, value),
  };
}

function mountApp() {
  return mount(App, {
    global: {
      provide: {
        [PRODUCT_RUNTIME_KEY as symbol]: createMockRuntime(),
        [APPEARANCE_KEY as symbol]: createAppearance(memoryStorage()),
        [WINDOW_CHROME_PORT_KEY as symbol]: createWindowChromePort(),
        [CORE_CONFIG_GATEWAY_KEY as symbol]: createMockCoreConfigGateway(),
        [LOGS_GATEWAY_KEY as symbol]: createMockLogsGateway(),
      },
    },
  });
}

describe("App 壳（左侧栏导航可达性）", () => {
  it("左侧栏含「关于」入口，点击切到关于页并渲染品牌", async () => {
    const wrapper = mountApp();
    await flushPromises();

    const rail = wrapper.get('[data-testid="product-rail"]');
    const aboutButton = rail.findAll("button").find((button) => button.text() === "关于");
    expect(aboutButton).toBeDefined();
    // 初始页为「连接」，关于页内容尚未渲染。
    expect(wrapper.text()).not.toContain("EXV VPN");

    await aboutButton!.trigger("click");
    await flushPromises();

    expect(wrapper.get("#about-title").text()).toBe("EXV");
    expect(wrapper.get("#about-title").text()).not.toContain("EXV VPN");
    expect(wrapper.text()).toContain("for ECNU");
    expect(wrapper.get('[data-testid="about-version"]').text().trim().length).toBeGreaterThan(0);
  });
});
