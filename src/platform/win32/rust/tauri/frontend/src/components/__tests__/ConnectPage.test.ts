import { readFileSync } from "node:fs";

import { flushPromises, mount } from "@vue/test-utils";
import { ref, type Ref } from "vue";
import { beforeEach, describe, expect, it, vi, type Mock } from "vitest";

import ConnectPage from "../../pages/ConnectPage.vue";
import ProductRail from "../ProductRail.vue";
import ToastStack from "../ToastStack.vue";
import { clearToasts } from "../../lib/toast";
import { present } from "../../product/presenter";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../../product/runtime";
import { resetAuthModalDismissed } from "../../product/ui-transient";
import type { ProductUiState } from "../../product/types";
import type { ServiceControlReply } from "../../lib/ipc";
import {
  snapshotConnected,
  snapshotConnecting,
  snapshotFailedClean,
  snapshotFailedDirty,
  snapshotIdle,
  snapshotUnauthorized,
} from "../../test/fixtures";

type RuntimeOverrides = Partial<{
  connect: Mock;
  stop: Mock;
  serviceControl: Mock;
}>;

function createRuntime(state: ProductUiState, overrides: RuntimeOverrides = {}) {
  const connect = vi.fn(async () => undefined);
  const stop = vi.fn(async () => undefined);
  const triggerLatencyRefresh = vi.fn(async () => undefined);
  const serviceControl = vi.fn(
    async (): Promise<ServiceControlReply> => ({ service_status: null, ok: true, message: "ok" }),
  );
  const runtime: ProductRuntime = {
    source: "mock",
    state: ref(state) as Ref<ProductUiState>,
    start: async () => undefined,
    connect: overrides.connect ?? connect,
    stop: overrides.stop ?? stop,
    triggerLatencyRefresh,
    serviceControl: overrides.serviceControl ?? serviceControl,
    dispose: () => undefined,
  };

  // 返回与 runtime 实际使用的同一 mock（overrides 注入时断言用），否则调用方拿到的
  // 是本地默认 mock（从不被调用）。
  return {
    runtime,
    connect: overrides.connect ?? connect,
    stop: overrides.stop ?? stop,
    triggerLatencyRefresh,
    serviceControl: overrides.serviceControl ?? serviceControl,
  };
}

function productState(snapshot: Parameters<typeof present>[0]) {
  return present(snapshot, 61_000, {
    account: "preview-user",
    vpnServer: "vpn-cn.ecnu.edu.cn",
    campusIp: "10.88.88.5",
  });
}

function mountPage(state: ProductUiState, overrides: RuntimeOverrides = {}) {
  const fake = createRuntime(state, overrides);
  // 一并挂 ToastStack：非服务错误经右下角 toast 呈现（产品 UI 规则），断言走真实渲染。
  const wrapper = mount(
    { components: { ConnectPage, ToastStack }, template: "<ConnectPage /><ToastStack />" },
    {
      global: {
        provide: {
          [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime,
        },
      },
    },
  );

  return { wrapper, ...fake };
}

function mountRail(state: ProductUiState) {
  const fake = createRuntime(state);
  const wrapper = mount(ProductRail, {
    props: { currentPage: "connect" },
    global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
  });
  return wrapper;
}

describe("完整模式连接页", () => {
  beforeEach(() => {
    clearToasts();
    resetAuthModalDismissed();
  });

  it("主连接 hero 保留明确的顶部间距", () => {
    const heroSource = readFileSync("src/components/ProductConnectionHero.vue", "utf8");

    expect(heroSource).toMatch(/\.product-connection-hero\s*\{[\s\S]*?margin-top:\s*var\(--product-page-top-gap\);/);
  });

  it("连接页在 860×600 容器中保持有等距安全边距的弹性中段和操作栏", () => {
    const host = document.createElement("div");
    host.style.width = "860px";
    host.style.height = "600px";
    document.body.append(host);

    const fake = createRuntime(productState(snapshotConnecting("applying_platform_tunnel")));
    const wrapper = mount(ConnectPage, {
      attachTo: host,
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: fake.runtime } },
    });

    try {
      const page = wrapper.element as HTMLElement;
      const visualStage = wrapper.get('[data-testid="product-connection-visual-stage"]').element as HTMLElement;
      const layout = visualStage.parentElement as HTMLElement;
      const visual = visualStage.firstElementChild as HTMLElement;
      const stateVisual = wrapper.get('[data-testid="connection-visual-placeholder"]').element as HTMLElement;
      const actionBar = wrapper.get('[data-testid="product-action-bar"]').element as HTMLElement;

      const hostStyle = getComputedStyle(host);
      const pageStyle = getComputedStyle(page);
      const layoutStyle = getComputedStyle(layout);
      const visualStageStyle = getComputedStyle(visualStage);
      const visualStyle = getComputedStyle(visual);
      const stateVisualStyle = getComputedStyle(stateVisual);
      const actionBarStyle = getComputedStyle(actionBar);

      expect(hostStyle.width).toBe("860px");
      expect(hostStyle.height).toBe("600px");
      expect(pageStyle.height).toBe("100%");
      expect(pageStyle.minHeight).toBe("0");
      expect(pageStyle.flexDirection).toBe("column");
      expect(layoutStyle.flexGrow).toBe("1");
      expect(layoutStyle.flexShrink).toBe("1");
      expect(layoutStyle.minHeight).toBe("0");
      expect(layoutStyle.overflowY).toBe("auto");
      expect(layoutStyle.overscrollBehavior).toBe("contain");
      expect(visualStageStyle.height).toBe("100%");
      expect(visualStageStyle.minHeight).toBe("0");
      expect(visualStyle.height).toBe("100%");
      expect(visualStyle.minHeight).toBe("0");
      expect(stateVisualStyle.height).toBe("100%");
      expect(actionBarStyle.flexShrink).toBe("0");
      expect(actionBarStyle.marginTop).toBe("0px");
    } finally {
      wrapper.unmount();
      host.remove();
    }
  });

  it("连接中展示恰好八个阶段及其语义，不显示冗余进度标题或流量", () => {
    const { wrapper } = mountPage(productState(snapshotConnecting("applying_platform_tunnel")));
    const stages = wrapper.findAll('[data-testid="stage-item"]');

    expect(stages).toHaveLength(8);
    expect(stages.filter((item) => item.attributes("data-stage-visual") === "complete")).toHaveLength(5);
    expect(stages.filter((item) => item.attributes("data-stage-visual") === "current")).toHaveLength(1);
    expect(stages.filter((item) => item.attributes("data-stage-visual") === "waiting")).toHaveLength(2);
    expect(wrapper.text()).not.toContain("连接过程");
    expect(wrapper.text()).not.toContain("八个阶段");
    expect(wrapper.find('[data-testid="traffic-metrics"]').exists()).toBe(false);
  });

  it("未连接时不展示阶段或流量", () => {
    const { wrapper } = mountPage(productState(snapshotIdle()));

    expect(wrapper.findAll('[data-testid="stage-item"]')).toHaveLength(0);
    expect(wrapper.find('[data-testid="traffic-metrics"]').exists()).toBe(false);
  });

  it("连接页使用产品级视觉壳但仍只消费 ProductUiState", () => {
    const { wrapper } = mountPage(productState(snapshotConnected()));

    expect(wrapper.find('[data-testid="product-connection-hero"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="product-connection-visual-stage"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="product-action-bar"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="product-connection-hero"]').text()).toContain("已连接");
  });

  it("仅在服务未安装时显示安装服务后连接 checkbox，且不显示正式服务管理面板", async () => {
    const page = mountPage(
      productState(snapshotIdle({ service_status: { installed: false, state: "stopped" } })),
    );

    expect(page.wrapper.find('[data-testid="service-panel"]').exists()).toBe(false);
    expect(page.wrapper.find('[data-testid="service-auto-install-option"]').exists()).toBe(true);
    expect(page.wrapper.get('[data-testid="service-auto-install"]').element).toHaveProperty("checked", false);

    await page.wrapper.get('[data-testid="service-auto-install"]').setValue(true);
    await page.wrapper.get('[data-testid="connection-action"]').trigger("click");
    expect(page.serviceControl).toHaveBeenCalledWith("install");
    expect(page.connect).toHaveBeenCalledTimes(1);
  });

  it("服务已安装时不显示连接页安装 checkbox", () => {
    const { wrapper } = mountPage(
      productState(snapshotIdle({ service_status: { installed: true, state: "running" } })),
    );

    expect(wrapper.find('[data-testid="service-panel"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="service-auto-install-option"]').exists()).toBe(false);
  });

  it("已连接时显示来自 presenter 的真实流量，不展示阶段", () => {
    const page = mountPage(productState(snapshotConnected({ rx_rate_bps: 4_096 })));
    const wrapper = mountRail(productState(snapshotConnected({ rx_rate_bps: 4_096 })));

    expect(page.wrapper.findAll('[data-testid="stage-item"]')).toHaveLength(0);
    const metrics = wrapper.get('[data-testid="traffic-metrics"]').text();
    expect(metrics).toContain("4 KB/s");
    expect(metrics).toContain("4 KB");
    expect(metrics).not.toContain("上传");
    expect(metrics).not.toContain("下载");
  });

  it("已连接但统计不可用时保留连接身份，不伪造占位统计", () => {
    const wrapper = mountRail(productState(snapshotConnected({}, { stats: null })));

    expect(wrapper.find('[data-testid="traffic-metrics"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="traffic-metrics"]').text()).toContain("账户");
    expect(wrapper.text()).not.toContain("统计暂不可用");
    expect(wrapper.text()).not.toContain("0 B");
  });

  it("disconnected 极简侧栏只显示状态 pill，隐藏环境/重连/unimplemented（即使快照携带真实重连）", () => {
    const wrapper = mountRail(
      productState({
        ...snapshotIdle(),
        proxy_tun: {
          detected: true,
          adapters: [
            {
              name: "Mihomo",
              description: "Wintun Userspace Tunnel",
              if_index: 12,
              kind: "proxy_tun",
            },
          ],
          route_policy: "exv-before-proxy-tun",
        },
        system_proxy: { mode: "automatic", endpoint_count: 3, bypass_merged: true, topology: "t2" },
        reconnect: { auto_reconnect: true, max_attempts: 5, current_attempt: 1, active: true },
      }),
    );

    expect(wrapper.find('[data-testid="connection-status-pill"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="connection-status-pill"]').text()).toContain("未连接");
    expect(wrapper.findAll('[data-testid="unimplemented-value"]')).toHaveLength(0);
    expect(wrapper.find('[data-testid="user-avatar"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain("DTLS");
    expect(wrapper.text()).not.toContain("已检测到");
    expect(wrapper.text()).not.toContain("环境检测");
    expect(wrapper.text()).not.toContain("自动重连");
    expect(wrapper.text()).not.toContain("重连中");
    const environment = wrapper.get('[data-testid="sidebar-environment"]');
    expect(environment.text()).toContain("系统代理");
    expect(environment.text()).toContain("TUN");
    expect(environment.get('[data-testid="system-proxy-status"]').attributes("data-enabled")).toBe("true");
  });

  it("重连激活时连接页环境摘要显示重连次数", () => {
    const { wrapper } = mountPage(
      productState({
        ...snapshotConnected(),
        reconnect: { auto_reconnect: true, max_attempts: 5, current_attempt: 2, active: true },
      }),
    );

    const reconnect = wrapper.get('[data-testid="reconnect-status"]');
    expect(reconnect.text()).toContain("重连中 · 第 2 次");
  });

  it("重连仅开启（非激活）时显示已重连次数", () => {
    const { wrapper } = mountPage(
      productState({
        ...snapshotIdle(),
        reconnect: { auto_reconnect: true, max_attempts: 0, current_attempt: 0, active: false },
      }),
    );

    const reconnect = wrapper.get('[data-testid="reconnect-status"]');
    expect(reconnect.text()).toContain("已重连 0 次");
  });

  it("快照未携带重连时环境摘要不显示重连项", () => {
    const { wrapper } = mountPage(productState(snapshotIdle()));

    expect(wrapper.find('[data-testid="reconnect-status"]').exists()).toBe(false);
  });

  it("按连接、取消与断开状态路由唯一的运行时动作", async () => {
    const idle = mountPage(productState(snapshotIdle()));
    await idle.wrapper.get('[data-testid="connection-action"]').trigger("click");
    expect(idle.connect).toHaveBeenCalledTimes(1);
    expect(idle.stop).not.toHaveBeenCalled();

    const connecting = mountPage(productState(snapshotConnecting("connecting_control")));
    expect(connecting.wrapper.get('[data-testid="connection-action"]').text()).toBe("取消");
    await connecting.wrapper.get('[data-testid="connection-action"]').trigger("click");
    expect(connecting.connect).not.toHaveBeenCalled();
    expect(connecting.stop).toHaveBeenCalledTimes(1);

    const connected = mountPage(productState(snapshotConnected()));
    expect(connected.wrapper.get('[data-testid="connection-action"]').text()).toBe("断开");
    await connected.wrapper.get('[data-testid="connection-action"]').trigger("click");
    expect(connected.connect).not.toHaveBeenCalled();
    expect(connected.stop).toHaveBeenCalledTimes(1);
  });

  it("干净/脏失败都显示重试并重新连接（不禁用按钮）", async () => {
    const clean = mountPage(productState(snapshotFailedClean()));
    const cleanButton = clean.wrapper.get('[data-testid="connection-action"]');
    expect(cleanButton.text()).toBe("重试");
    await cleanButton.trigger("click");
    expect(clean.connect).toHaveBeenCalledTimes(1);
    expect(clean.stop).not.toHaveBeenCalled();

    const dirty = mountPage(productState(snapshotFailedDirty()));
    const dirtyButton = dirty.wrapper.get('[data-testid="connection-action"]');
    expect(dirtyButton.text()).toBe("重试");
    expect(dirtyButton.attributes("disabled")).toBeUndefined();
    await dirtyButton.trigger("click");
    expect(dirty.connect).toHaveBeenCalledTimes(1);
    expect(dirty.stop).not.toHaveBeenCalled();
  });

  it("未授权失败弹认证模态，展示可执行处理说明（不页内插入组件）", () => {
    const { wrapper } = mountPage(productState(snapshotUnauthorized()));

    const modal = wrapper.get('[data-testid="auth-failure-modal"]');
    expect(modal.text()).toContain("VPN 网关没有通过本次登录");
    expect(modal.text()).toContain("检查并保存服务器、用户名和密码");
    expect(modal.text()).toContain("返回连接页后再次点击“连接”");
    expect(modal.text()).toContain("点击“修复”");
  });

  it("认证模态可关闭，关闭后按钮保留「重试」可点（无恢复路径死锁）", async () => {
    const { wrapper, connect } = mountPage(productState(snapshotUnauthorized()), {
      connect: vi.fn(async () => undefined),
    });
    expect(wrapper.find('[data-testid="auth-failure-modal"]').exists()).toBe(true);

    await wrapper.get('[data-testid="auth-failure-close"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="auth-failure-modal"]').exists()).toBe(false);

    const button = wrapper.get('[data-testid="connection-action"]');
    expect(button.text()).toBe("重试");
    expect(button.attributes("disabled")).toBeUndefined();
    await button.trigger("click");
    expect(connect).toHaveBeenCalledTimes(1);
  });

  it("认证模态关闭后页面切走再切回不重弹（模块级关闭标记，未再点连接不弹）", async () => {
    const first = mountPage(productState(snapshotUnauthorized()));
    expect(first.wrapper.find('[data-testid="auth-failure-modal"]').exists()).toBe(true);
    await first.wrapper.get('[data-testid="auth-failure-close"]').trigger("click");
    await flushPromises();
    first.wrapper.unmount();

    // 重新挂载（等价于从设置页切回连接页）——模态不应重弹。
    const second = mountPage(productState(snapshotUnauthorized()));
    await flushPromises();
    expect(second.wrapper.find('[data-testid="auth-failure-modal"]').exists()).toBe(false);

    // 发起新动作后才允许下次失败重弹。
    second.wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();
    expect(second.wrapper.find('[data-testid="auth-failure-modal"]').exists()).toBe(true);
  });

  it("运行时动作进行中禁用按钮，并将失败显示为短错误文本", async () => {
    let rejectConnect: (reason: Error) => void = () => undefined;
    const connect = vi.fn(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectConnect = reject;
        }),
    );
    const { wrapper } = mountPage(productState(snapshotIdle()), { connect });
    const button = wrapper.get('[data-testid="connection-action"]');

    await button.trigger("click");
    expect(button.attributes("disabled")).toBeDefined();
    expect(button.attributes("aria-busy")).toBe("true");
    await button.trigger("click");
    expect(connect).toHaveBeenCalledTimes(1);

    rejectConnect(new Error("模拟失败"));
    await flushPromises();
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("模拟失败"))).toBe(true);
  });

  it("Tauri 命令拒绝以 {kind,message} 对象到达时显示真实错误而非兜底", async () => {
    const connect = vi.fn(
      () => Promise.reject({ kind: "failed_precondition", message: "服务已安装但未运行" }),
    );
    const { wrapper } = mountPage(productState(snapshotIdle()), { connect });

    await wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();

    const toasts = wrapper.findAll('[data-testid="toast"]');
    expect(toasts.some((t) => t.text().includes("服务已安装但未运行"))).toBe(true);
    expect(toasts.every((t) => !t.text().includes("请稍后重试"))).toBe(true);
  });

  it("R5 服务模式连接失败（service_not_running）弹恢复 modal，非服务错误不弹", async () => {
    const connect = vi.fn()
      .mockRejectedValueOnce({ kind: "service_not_running", message: "服务已安装但未运行，请启动服务" })
      .mockResolvedValue(undefined);
    const { wrapper } = mountPage(productState(snapshotIdle()), { connect });

    await wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();

    const modal = wrapper.find('[data-testid="service-failure-modal"]');
    expect(modal.exists()).toBe(true);
    expect(modal.get('[data-testid="service-failure-error"]').text()).toContain("服务已安装但未运行");

    // 非服务错误（failed_precondition 无前缀）不弹 modal。
    const connectPlain = vi.fn(
      () => Promise.reject({ kind: "failed_precondition", message: "其他前置错误" }),
    );
    const plain = mountPage(productState(snapshotIdle()), { connect: connectPlain });
    await plain.wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();
    expect(plain.wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(false);
    expect(plain.wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("其他前置错误"))).toBe(true);
  });

  it("R5 清理服务后连接：uninstall → connect 按序派发，成功后关闭 modal 并清除错误", async () => {
    const connect = vi.fn()
      .mockRejectedValueOnce({ kind: "service_not_running", message: "服务已安装但未运行" })
      .mockResolvedValue(undefined);
    const { wrapper, serviceControl, connect: connectSpy } = mountPage(productState(snapshotIdle()), {
      connect,
    });

    await wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(true);

    await wrapper.get('[data-testid="service-failure-clean"]').trigger("click");
    await flushPromises();

    expect(serviceControl.mock.calls).toEqual([["uninstall"]]);
    expect(connectSpy).toHaveBeenCalledTimes(2);
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(false);
    // 服务恢复路径无 toast（错误经 modal 呈现；恢复成功无残留）。
    expect(wrapper.findAll('[data-testid="toast"]').length).toBe(0);
  });

  it("R5 重装服务后连接：install（Core bootstrap，内部处理运行中服务）→ connect 按序派发，成功后关闭 modal", async () => {
    const connect = vi.fn()
      .mockRejectedValueOnce({ kind: "service_connect_failed", message: "服务引擎连接失败" })
      .mockResolvedValue(undefined);
    const { wrapper, serviceControl, connect: connectSpy } = mountPage(productState(snapshotIdle()), {
      connect,
    });

    await wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(true);

    await wrapper.get('[data-testid="service-failure-reinstall"]').trigger("click");
    await flushPromises();

    expect(serviceControl.mock.calls).toEqual([["install"]]);
    expect(connectSpy).toHaveBeenCalledTimes(2);
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(false);
  });

  it("R5 取消：仅关闭 modal，不派发任何请求，无残留错误呈现", async () => {
    const connect = vi.fn(
      () => Promise.reject({ kind: "service_not_running", message: "服务已安装但未运行" }),
    );
    const { wrapper, serviceControl } = mountPage(productState(snapshotIdle()), { connect });

    await wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(true);

    await wrapper.get('[data-testid="service-failure-cancel"]').trigger("click");
    await flushPromises();

    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(false);
    expect(serviceControl).not.toHaveBeenCalled();
    // 服务恢复路径错误只经 modal 呈现；关闭后无残留（按钮保留「重试」可用）。
    expect(wrapper.findAll('[data-testid="toast"]').length).toBe(0);
  });

  it("R5 恢复序列中途失败：错误显示在 modal 内，modal 保持打开且不派发 connect", async () => {
    const connect = vi.fn(
      () => Promise.reject({ kind: "service_not_running", message: "服务已安装但未运行" }),
    );
    const serviceControl = vi.fn(
      async () => ({ service_status: null, ok: false, message: "卸载服务失败。" }),
    );
    const { wrapper, connect: connectSpy } = mountPage(productState(snapshotIdle()), {
      connect,
      serviceControl,
    });

    await wrapper.get('[data-testid="connection-action"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(true);

    await wrapper.get('[data-testid="service-failure-clean"]').trigger("click");
    await flushPromises();

    expect(serviceControl).toHaveBeenCalledWith("uninstall");
    expect(connectSpy).toHaveBeenCalledTimes(1); // 仅最初失败的 connect，未派发恢复连接
    expect(wrapper.find('[data-testid="service-failure-modal"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="service-failure-action-error"]').text()).toContain(
      "卸载服务失败",
    );
  });

  it("点击后立刻禁用按钮，不等后端返回", async () => {
    let resolveConnect: () => void = () => undefined;
    const connect = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveConnect = resolve;
        }),
    );
    const { wrapper } = mountPage(productState(snapshotIdle()), { connect });
    const button = wrapper.get('[data-testid="connection-action"]');

    await button.trigger("click");
    expect(button.attributes("disabled")).toBeDefined();

    resolveConnect();
    await flushPromises();
    expect(button.attributes("disabled")).toBeUndefined();
  });

  it("中间视觉区诚实显示 UI 待设计，移除伪坐标、网格、椭圆和说明文字", () => {
    const { wrapper } = mountPage(productState(snapshotConnected()));
    const source = readFileSync("src/components/ProductConnectionVisualStage.vue", "utf8");

    expect(wrapper.get('[data-testid="connection-visual-placeholder"]').text()).toBe("UI 待设计");
    expect(wrapper.find(".product-connection-visual-stage__grid").exists()).toBe(false);
    expect(wrapper.find(".product-connection-visual-stage__axis").exists()).toBe(false);
    expect(wrapper.find(".soft-outline").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("稳定安全通道已闭合");
    expect(source).not.toContain('import ConnectionStateVisual');
    expect(source).not.toContain('product-connection-visual-stage__grid');
    expect(source).not.toContain('product-connection-visual-stage__axis');
  });

  it("页面只依赖 ProductRuntime，不得绕过 presenter 重复接线或格式化", () => {
    const source = readFileSync("src/pages/ConnectPage.vue", "utf8");

    expect(source).not.toMatch(/from\s+["']\.\.\/lib\/ipc["']/);
    expect(source).not.toMatch(/\b(?:kernel|onStatus|snapshot|stats|activeOpId|terminalReached)\b/);
    expect(source).not.toMatch(/\bformat(?:Bytes|Rate)\b/);
  });

  it("阶段表始终保持两列四行，不在窄宽度退化成单列", () => {
    const source = readFileSync("src/components/ConnectionStageList.vue", "utf8");

    expect(source).toContain("grid-template-columns: repeat(2, minmax(0, 1fr));");
    expect(source).not.toContain("grid-template-columns: 1fr;");
  });

  it("当前阶段以黄色转圈表达进行中，并且只旋转图形本身", () => {
    const source = readFileSync("src/components/ConnectionStageList.vue", "utf8");

    expect(source).toMatch(/@keyframes\s+stage-ring-spin/);
    expect(source).toMatch(/animation:\s*stage-ring-spin\s+440ms\s+linear\s+infinite/);
    expect(source).toMatch(/transform:\s*rotate\(/);
  });

  it("新连接组件不重新引入背景、边框或文字颜色的过渡", () => {
    const actionSource = readFileSync("src/components/ConnectionActionButton.vue", "utf8");
    const stageSource = readFileSync("src/components/ConnectionStageList.vue", "utf8");

    expect(actionSource).not.toMatch(/(?:background-color|border-color|color)\s+var\(--motion-/);
    expect(stageSource).not.toMatch(/(?:background-color|border-color|color)\s+var\(--motion-/);
  });

  it("连接页以统一间距分隔 hero、中间区、操作栏和物理底边", () => {
    const source = readFileSync("src/pages/ConnectPage.vue", "utf8");

    expect(source).toMatch(/\.connect-page\s*\{[^}]*--connect-section-gap:\s*var\(--space-5\);[^}]*gap:\s*var\(--connect-section-gap\);[^}]*padding-bottom:\s*var\(--connect-section-gap\);/);
    expect(source).toMatch(/\.connection-layout\s*\{[^}]*margin-top:\s*0;/);
    expect(source).toMatch(/\.connect-page__action-bar\s*\{[^}]*margin-top:\s*0;[^}]*margin-bottom:\s*0;/);
  });
});
