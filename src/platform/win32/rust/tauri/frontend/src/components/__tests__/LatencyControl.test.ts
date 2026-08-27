import { flushPromises, mount } from "@vue/test-utils";
import { ref } from "vue";
import { describe, expect, it, vi } from "vitest";

import { present } from "../../product/presenter";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../../product/runtime";
import { snapshotConnected } from "../../test/fixtures";
import LatencyControl from "../LatencyControl.vue";

function connectedProductState() {
  return present(
    snapshotConnected({ latency_ms: 24 }, {
      reconnect: { auto_reconnect: true, max_attempts: 3, current_attempt: 0, active: false },
    }),
    61_000,
  );
}

function createRuntime(triggerLatencyRefresh = vi.fn(async () => undefined)): ProductRuntime {
  return {
    source: "mock",
    state: ref(connectedProductState()),
    start: vi.fn(async () => undefined),
    connect: vi.fn(async () => undefined),
    stop: vi.fn(async () => undefined),
    triggerLatencyRefresh,
    serviceControl: vi.fn(async () => ({ service_status: null, ok: true, message: "ok" })),
    dispose: vi.fn(),
  };
}

function mountControl(runtime: ProductRuntime) {
  return mount(LatencyControl, {
    global: {
      provide: {
        [PRODUCT_RUNTIME_KEY as symbol]: runtime,
      },
    },
  });
}

describe("延迟检测控件（T1 迁入）", () => {
  it("已连接时直接展示真实时延并提供立即刷新，不再给出无法控制 engine 的伪开关", () => {
    const wrapper = mountControl(createRuntime());

    expect(wrapper.get('[data-testid="latency-value"]').text()).toBe("24 ms");
    expect(wrapper.find('[data-testid="latency-toggle"]').exists()).toBe(false);
    expect(wrapper.get('[data-testid="latency-refresh"]').text()).toContain("立即刷新");

    wrapper.unmount();
  });

  it("点击立即刷新触发 runtime 延迟刷新，并显示真实的请求已发送状态", async () => {
    const triggerLatencyRefresh = vi.fn(async () => undefined);
    const wrapper = mountControl(createRuntime(triggerLatencyRefresh));

    await wrapper.get('[data-testid="latency-refresh"]').trigger("click");
    await flushPromises();
    expect(triggerLatencyRefresh).toHaveBeenCalledTimes(1);
    expect(wrapper.get('[data-testid="latency-request-status"]').text()).toContain("已发送");

    wrapper.unmount();
  });
});
