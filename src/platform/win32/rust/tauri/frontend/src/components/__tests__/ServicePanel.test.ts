import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";

import ServicePanel from "../ServicePanel.vue";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../../product/runtime";
import type { ProductService } from "../../product/types";
import type { ServiceControlAction, ServiceControlReply } from "../../lib/ipc";
import * as toast from "../../lib/toast";

function fakeRuntime(overrides: Partial<Pick<ProductRuntime, "serviceControl">> = {}) {
  const calls: ServiceControlAction[] = [];
  const serviceControl = vi.fn(
    async (action: ServiceControlAction): Promise<ServiceControlReply> => {
      calls.push(action);
      return { service_status: null, ok: true, message: "ok" };
    },
  );
  const runtime: ProductRuntime = {
    source: "mock",
    state: undefined as never,
    start: async () => undefined,
    connect: async () => undefined,
    stop: async () => undefined,
    triggerLatencyRefresh: async () => undefined,
    serviceControl: overrides.serviceControl ?? serviceControl,
    dispose: () => undefined,
  };
  return { runtime, serviceControl, calls };
}

async function mountPanel(service: ProductService, autoInstall = false, busy = false) {
  const fake = fakeRuntime();
  const wrapper = mount(ServicePanel, {
    props: { service, autoInstall, busy },
    global: {
      provide: {
        [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime,
      },
    },
  });
  // 挂载时组件主动 query 一次（服务感知修复）；flush 后测试只断言用户动作调用。
  await flushPromises();
  return { wrapper, ...fake };
}

const running: ProductService = {
  status: { kind: "installed", scmState: "running", healthState: "healthy" },
  mode: "service",
};

const stopped: ProductService = {
  status: { kind: "installed", scmState: "stopped", healthState: null },
  mode: "oneshot",
};

const notInstalled: ProductService = {
  status: { kind: "not_installed" },
  mode: "auto",
};

const unknown: ProductService = {
  status: { kind: "unknown" },
  mode: "unknown",
};

describe("服务面板", () => {
  it("设置卡只展示服务状态，不渲染连接模式与二进制路径", async () => {
    const { wrapper } = await mountPanel(running);

    expect(wrapper.get('[data-testid="service-status"]').text()).toBe("运行中");
    expect(wrapper.find('[data-testid="service-mode"]').exists()).toBe(false);
    expect(wrapper.find(".mode-segment").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("连接模式");
    // R1：服务二进制路径已从 UI 永久摘除。
    expect(wrapper.find('[data-testid="service-binary-path"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain("二进制路径");
    expect(wrapper.text()).not.toContain("engine SCM 服务状态");
  });

  it("未安装时展示 checkbox 与安装按钮，不展示修复/卸载", async () => {
    const { wrapper } = await mountPanel(notInstalled);

    expect(wrapper.find('[data-testid="service-auto-install-option"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="service-install"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="service-repair"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="service-uninstall"]').exists()).toBe(false);
  });

  it("MED [3]：服务状态未知时禁用 checkbox 并提示回退 oneshot，不自动安装", async () => {
    const { wrapper } = await mountPanel(unknown);

    expect(wrapper.find('[data-testid="service-auto-install-option"]').exists()).toBe(false);
    expect(wrapper.get('[data-testid="service-unknown-note"]').text()).toContain("一次性连接");
    expect(wrapper.find('[data-testid="service-install"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="service-actions"]').text()).toBe("");
  });

  it("checkbox 勾选/取消经 update:autoInstall 通知连接页", async () => {
    const { wrapper } = await mountPanel(notInstalled, false);
    const input = wrapper.get('[data-testid="service-auto-install"]');

    await input.setValue(true);
    expect(wrapper.emitted("update:autoInstall")).toEqual([[true]]);

    await input.setValue(false);
    expect(wrapper.emitted("update:autoInstall")).toEqual([[true], [false]]);
  });

  it("M3 四态决策提示随服务状态与 checkbox 呈现", async () => {
    expect((await mountPanel(running)).wrapper.get('[data-testid="service-decision-hint"]').text()).toContain(
      "服务模式",
    );
    expect((await mountPanel(stopped)).wrapper.get('[data-testid="service-decision-hint"]').text()).toContain(
      "Core 会自动启动服务",
    );
    expect(
      (await mountPanel(notInstalled, true)).wrapper.get('[data-testid="service-decision-hint"]').text(),
    ).toContain("先安装服务再连接");
    expect(
      (await mountPanel(notInstalled, false)).wrapper.get('[data-testid="service-decision-hint"]').text(),
    ).toContain("一次性连接");
    expect((await mountPanel(unknown)).wrapper.get('[data-testid="service-decision-hint"]').text()).toContain(
      "一次性连接",
    );
  });

  it("按钮按状态渲染：未安装=安装；已停止=修复+卸载；运行中=仅卸载", async () => {
    const installPanel = await mountPanel(notInstalled);
    expect(installPanel.wrapper.findAll(".service-actions button").map((b) => b.text())).toEqual(["安装"]);

    const stoppedPanel = await mountPanel(stopped);
    expect(stoppedPanel.wrapper.findAll(".service-actions button").map((b) => b.text())).toEqual(["修复", "卸载"]);

    const runningPanel = await mountPanel(running);
    expect(runningPanel.wrapper.findAll(".service-actions button").map((b) => b.text())).toEqual(["卸载"]);
  });

  it("MED [2]：修复已停止服务不先 stop（无运行中错位风险），直接 install", async () => {
    const { wrapper, calls } = await mountPanel(stopped);

    await wrapper.get('[data-testid="service-repair"]').trigger("click");
    await flushPromises();

    expect(calls).toEqual(["query", "install"]);
  });

  it("运行中的服务不提供修复按钮（正常无需修复）", async () => {
    const { wrapper } = await mountPanel(running);

    expect(wrapper.find('[data-testid="service-repair"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="service-start"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain("停止");
  });

  it("修复路径某步失败显示错误并停止后续步骤", async () => {
    const serviceControl = vi.fn(async (action: ServiceControlAction): Promise<ServiceControlReply> => {
      if (action === "install") {
        return { service_status: null, ok: false, message: "安装服务失败。" };
      }
      return { service_status: null, ok: true, message: "ok" };
    });
    const fake = fakeRuntime({ serviceControl });
    const wrapper = mount(ServicePanel, {
      props: { service: stopped, autoInstall: false, busy: false },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });
    const pushToastSpy = vi.spyOn(toast, "pushToast");

    await wrapper.get('[data-testid="service-repair"]').trigger("click");
    await flushPromises();

    // 挂载 query + 用户 install（不再先停服务）。
    expect(serviceControl).toHaveBeenCalledTimes(2);
    expect(serviceControl.mock.calls.map(([a]) => a)).toEqual(["query", "install"]);
    expect(pushToastSpy).toHaveBeenCalledWith("安装服务失败。", "error");
  });

  it("连接主动作进行中时禁用服务按钮", async () => {
    const { wrapper } = await mountPanel(stopped, false, true);

    expect(wrapper.get('[data-testid="service-repair"]').attributes("disabled")).toBeDefined();
    expect(wrapper.get('[data-testid="service-uninstall"]').attributes("disabled")).toBeDefined();
  });

  it("Tauri 命令拒绝以 {kind,message} 对象到达时显示真实错误而非兜底", async () => {
    const serviceControl = vi.fn(
      (_action: ServiceControlAction) =>
        Promise.reject({ kind: "internal", message: "安装服务失败：SCM 拒绝。" }),
    );
    const fake = fakeRuntime({ serviceControl });
    const wrapper = mount(ServicePanel, {
      props: { service: notInstalled, autoInstall: false, busy: false },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });
    const pushToastSpy = vi.spyOn(toast, "pushToast");

    await wrapper.get('[data-testid="service-install"]').trigger("click");
    await flushPromises();

    expect(pushToastSpy).toHaveBeenCalledWith("安装服务失败：SCM 拒绝。", "error");
    expect(pushToastSpy.mock.calls[0][0]).not.toContain("请稍后重试");
  });

  it("点击安装后立刻禁用按钮并显示操作中占位，不等后端返回", async () => {
    let resolveInstall: (reply: ServiceControlReply) => void = () => undefined;
    const serviceControl = vi.fn(
      () =>
        new Promise<ServiceControlReply>((resolve) => {
          resolveInstall = resolve;
        }),
    );
    const fake = fakeRuntime({ serviceControl });
    const wrapper = mount(ServicePanel, {
      props: { service: notInstalled, autoInstall: false, busy: false },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });
    const pushToastSpy = vi.spyOn(toast, "pushToast");
    const installButton = wrapper.get('[data-testid="service-install"]');

    await installButton.trigger("click");
    expect(installButton.attributes("disabled")).toBeDefined();
    expect(wrapper.find('[data-testid="service-operation-overlay"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="service-operation-overlay"]').text()).toContain("正在安装");

    resolveInstall({ service_status: null, ok: true, message: "batch completed" });
    await flushPromises();
    expect(pushToastSpy).toHaveBeenCalledWith("服务安装完成。", "success");
    expect(wrapper.find('[data-testid="service-operation-overlay"]').exists()).toBe(false);
  });

  it("showConnectOptions=false 时隐藏连接页专属 checkbox 与决策提示，保留操作按钮", async () => {
    const fake = fakeRuntime();
    const wrapper = mount(ServicePanel, {
      props: { service: notInstalled, autoInstall: false, busy: false, showConnectOptions: false },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });

    expect(wrapper.find('[data-testid="service-auto-install-option"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="service-decision-hint"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="service-install"]').exists()).toBe(true);
  });

  it("非 query 操作显示模态遮罩，完成后消失", async () => {
    // 使用延迟 promise 使 overlay 在操作期间保持可见
    let resolveInstall: (reply: ServiceControlReply) => void = () => undefined;
    const serviceControl = vi.fn(
      () =>
        new Promise<ServiceControlReply>((resolve) => {
          resolveInstall = resolve;
        }),
    );
    const fake = fakeRuntime({ serviceControl });
    const wrapper = mount(ServicePanel, {
      props: { service: stopped, autoInstall: false, busy: false },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });

    await wrapper.get('[data-testid="service-repair"]').trigger("click");
    // overlay 应在操作期间可见
    expect(wrapper.find('[data-testid="service-operation-overlay"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="service-operation-overlay"]').text()).toContain("正在修复");

    // 完成后 overlay 消失
    resolveInstall({ service_status: null, ok: true, message: "ok" });
    await flushPromises();
    expect(wrapper.find('[data-testid="service-operation-overlay"]').exists()).toBe(false);
  });

  it("install 成功后显示成功 toast", async () => {
    const { wrapper } = await mountPanel(notInstalled);
    const pushToastSpy = vi.spyOn(toast, "pushToast");

    await wrapper.get('[data-testid="service-install"]').trigger("click");
    await flushPromises();

    expect(pushToastSpy).toHaveBeenCalledWith("服务安装完成。", "success");
  });

  it("install 失败后显示错误 toast", async () => {
    const serviceControl = vi.fn(
      async (): Promise<ServiceControlReply> => ({
        service_status: null,
        ok: false,
        message: "安装服务失败。",
      }),
    );
    const fake = fakeRuntime({ serviceControl });
    const wrapper = mount(ServicePanel, {
      props: { service: notInstalled, autoInstall: false, busy: false },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });
    const pushToastSpy = vi.spyOn(toast, "pushToast");

    await wrapper.get('[data-testid="service-install"]').trigger("click");
    await flushPromises();

    expect(pushToastSpy).toHaveBeenCalledWith("安装服务失败。", "error");
  });

  it("uninstall 成功后显示友好文案 toast", async () => {
    const { wrapper } = await mountPanel(stopped);
    const pushToastSpy = vi.spyOn(toast, "pushToast");

    await wrapper.get('[data-testid="service-uninstall"]').trigger("click");
    await flushPromises();

    expect(pushToastSpy).toHaveBeenCalledWith("服务卸载完成。", "success");
  });
});
