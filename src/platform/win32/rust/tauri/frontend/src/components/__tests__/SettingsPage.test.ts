import { readFileSync } from "node:fs";

import { flushPromises, mount } from "@vue/test-utils";
import { nextTick, ref } from "vue";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ToastStack from "../ToastStack.vue";
import { clearToasts } from "../../lib/toast";
import type { ServiceControlAction, ServiceControlReply } from "../../lib/ipc";
import SettingsPage from "../../pages/SettingsPage.vue";
import { APPEARANCE_KEY, createAppearance } from "../../product/appearance";
import { CORE_CONFIG_GATEWAY_KEY, type CoreConfigGateway } from "../../product/core-config";
import { present } from "../../product/presenter";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../../product/runtime";
import { resetSettingsState } from "../../product/settings-state";
import {
  provideUiPrefsGateway,
  resetUiPrefsState,
} from "../../product/ui-prefs";
import { snapshotIdle } from "../../test/fixtures";

/** 挂设置页 + ToastStack（保存反馈走 toast；断言走真实渲染）。 */
function mountSettings(
  gateway: ReturnType<typeof configGateway>,
  localAppearance = appearance(),
  extra: { runtime?: ProductRuntime } = {},
) {
  const props = { gateway, appearance: localAppearance };
  const provide: Record<symbol, unknown> = {};
  if (extra.runtime) provide[PRODUCT_RUNTIME_KEY as symbol] = extra.runtime;
  const wrapper = mount(
    {
      components: { SettingsPage, ToastStack },
      props: ["gateway", "appearance"],
      template: '<SettingsPage :gateway="gateway" :appearance="appearance" /><ToastStack />',
    },
    { props, global: { provide } },
  );
  return wrapper;
}

function appearance() {
  const values = new Map<string, string>();
  return createAppearance({
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  });
}

function configGateway(
  items: ReadonlyArray<{ key: string; value: string }>,
  result: boolean | Error = true,
): CoreConfigGateway & { configGet: ReturnType<typeof vi.fn>; configSet: ReturnType<typeof vi.fn> } {
  return {
    configGet: vi.fn(async () => items),
    configSet: vi.fn(async () => {
      if (result instanceof Error) throw result;
      return result;
    }),
  };
}

describe("高密度设置页", () => {
  beforeEach(() => {
    clearToasts();
    resetSettingsState();
  });
  it("只给已知核心键提供可编辑控件，并把外观保留在本地", async () => {
    const gateway = configGateway([
      { key: "server", value: "vpn.ecnu.edu.cn" },
      { key: "remember_password", value: "true" },
      { key: "mtu", value: "1420" },
    ]);
    const localAppearance = appearance();
    const wrapper = mount(SettingsPage, { props: { gateway, appearance: localAppearance } });
    await flushPromises();

    expect(wrapper.get('[data-testid="setting-server"]').find("select").exists()).toBe(true);
    expect(wrapper.get('[data-testid="setting-remember_password"]').find('input[type="checkbox"]').exists()).toBe(true);
    expect(gateway.configSet).not.toHaveBeenCalled();

    localAppearance.setTheme("dark");
    expect(gateway.configSet).not.toHaveBeenCalled();
  });

  it("修改 Core 配置后页顶出现「保存设置」，点击批量提交；未修改时不出现", async () => {
    const gateway = configGateway([{ key: "mtu", value: "1420" }]);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
    await wrapper.get('[data-testid="input-mtu"]').setValue("1400");
    await flushPromises();
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);

    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();

    expect(gateway.configSet).toHaveBeenCalledWith([{ key: "mtu", value: "1400" }]);
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("设置已保存"))).toBe(true);
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
  });

  it("外观（本地）改动即时生效，不触发「保存设置」；Core 配置改动才显示保存", async () => {
    const gateway = configGateway([{ key: "server", value: "vpn.ecnu.edu.cn" }]);
    const localAppearance = appearance();
    const wrapper = mountSettings(gateway, localAppearance);
    await flushPromises();

    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
    await wrapper.get('[data-testid="appearance-accent-violet"]').trigger("click");
    await flushPromises();
    expect(localAppearance.state.value.accent).toBe("violet");
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
    expect(gateway.configSet).not.toHaveBeenCalled();

    // 已存值不在预设中 → 归一到「自定义」，文本框手填触发保存。
    await wrapper.get('[data-testid="input-server-custom"]').setValue("vpn2.ecnu.edu.cn");
    await flushPromises();
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);
  });

  it("设置状态内存持久化：切页重挂载保留草稿与保存入口，不重新读取覆盖", async () => {
    const gateway = configGateway([{ key: "server", value: "vpn.ecnu.edu.cn" }]);
    const wrapper = mountSettings(gateway);
    await flushPromises();
    await wrapper.get('[data-testid="input-server-custom"]').setValue("vpn2.ecnu.edu.cn");
    await flushPromises();
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);
    wrapper.unmount();

    const second = mountSettings(gateway);
    await flushPromises();
    const serverInput = second.get('[data-testid="input-server-custom"]').element as HTMLInputElement;
    expect(serverInput.value).toBe("vpn2.ecnu.edu.cn");
    expect(second.find('[data-testid="save-all-settings"]').exists()).toBe(true);
    expect(gateway.configGet).toHaveBeenCalledTimes(1);
  });

  it("VPN 服务器为预设+自定义下拉：预设命中选中、自定义可手填、保存归一化", async () => {
    const gateway = configGateway([{ key: "server", value: "vpn-cn.ecnu.edu.cn" }]);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    const row = wrapper.get('[data-testid="setting-server"]');
    const select = row.get('[data-testid="input-server"]');
    // 下拉直接显示服务器地址；预设 + 自定义选项齐全；描述更新。
    expect(row.text()).toContain("VPN 服务器");
    expect(row.text()).toContain("vpn-cn.ecnu.edu.cn");
    expect(row.text()).toContain("vpn-ct.ecnu.edu.cn");
    expect(row.text()).toContain("vpn-lt.ecnu.edu.cn");
    expect(row.text()).toContain("自定义");
    expect(row.text()).not.toContain("可选预设或自定义");
    // 命中预设 → 选中该预设，不显示自定义文本框。
    expect((select.element as HTMLSelectElement).value).toBe("vpn-cn.ecnu.edu.cn");
    expect(wrapper.find('[data-testid="input-server-custom"]').exists()).toBe(false);

    // 切换预设 → 草稿更新并出现保存入口。
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
    await select.setValue("vpn-ct.ecnu.edu.cn");
    await flushPromises();
    expect((row.get('[data-testid="input-server"]').element as HTMLSelectElement).value).toBe("vpn-ct.ecnu.edu.cn");
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);

    // 选「自定义」→ 展示文本框并保留当前值。
    await select.setValue("custom");
    await flushPromises();
    const custom = wrapper.get('[data-testid="input-server-custom"]');
    expect((custom.element as HTMLInputElement).value).toBe("vpn-ct.ecnu.edu.cn");

    // 手填带协议/尾部斜杠/大写 → 保存时归一化（去协议/去尾斜杠/小写）。
    await custom.setValue("HTTPS://VPN-LT.ECNU.EDU.CN/");
    await flushPromises();
    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();

    expect(gateway.configSet).toHaveBeenCalledWith([{ key: "server", value: "vpn-lt.ecnu.edu.cn" }]);
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("设置已保存"))).toBe(true);
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
  });

  it("密码框仅在勾选「记住密码」时展示；输入后随保存提交（core 不回显）", async () => {
    const gateway = configGateway([
      { key: "server", value: "vpn.ecnu.edu.cn" },
      { key: "remember_password", value: "true" },
    ]);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    expect(wrapper.find('[data-testid="input-password"]').exists()).toBe(true);
    const pwd = wrapper.get('[data-testid="input-password"]').element as HTMLInputElement;
    expect(pwd.type).toBe("password");
    expect(pwd.value).toBe("");

    // 取消记住密码 → 密码框隐藏
    await wrapper.get('[data-testid="input-remember_password"]').setValue(false);
    await flushPromises();
    expect(wrapper.find('[data-testid="input-password"]').exists()).toBe(false);

    // 重新勾选 → 密码框出现；输入后保存提交
    await wrapper.get('[data-testid="input-remember_password"]').setValue(true);
    await flushPromises();
    expect(wrapper.find('[data-testid="input-password"]').exists()).toBe(true);
    await wrapper.get('[data-testid="input-password"]').setValue("secret123");
    await flushPromises();
    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();
    expect(gateway.configSet).toHaveBeenCalledWith(
      expect.arrayContaining([{ key: "password", value: "secret123" }]),
    );
  });

  it.each([false, new Error("unauthenticated")])("保存失败时经 toast 报错，不显示已保存", async (result) => {
    const gateway = configGateway([{ key: "mtu", value: "1420" }], result);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    await wrapper.get('[data-testid="input-mtu"]').setValue("1400");
    await flushPromises();
    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();

    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("保存失败"))).toBe(true);
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("已保存"))).toBe(false);
  });

  it("右侧使用连续导航轴，页面本身不直接导入 kernel", () => {
    const source = readFileSync("src/pages/SettingsPage.vue", "utf8");

    expect(source).toContain("SettingsSectionAxis");
    expect(source).not.toMatch(/from\s+["']\.\.\/lib\/ipc["']/);
  });

  it("右侧导航轴基于滚动位置更新当前锚点，滚动到底强制激活最后分区", () => {
    const source = readFileSync("src/pages/SettingsPage.vue", "utf8");

    // 以滚动位置判定替代窄横带 IntersectionObserver：检测线 + 底部回退。
    expect(source).toContain("updateActiveSectionFromScroll");
    expect(source).toContain("sections[sections.length - 1].id");
    expect(source).toContain("activeSection.value =");
    expect(source).not.toContain("IntersectionObserver");
  });

  it("使用五个连续分区而不是横向标签页，并支持轴按钮激活", async () => {
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: appearance() } });
    await flushPromises();

    const axis = wrapper.get('[data-testid="settings-section-axis"]');
    const buttons = axis.findAll("button");
    expect(buttons).toHaveLength(5);
    expect(axis.find('[role="tab"]').exists()).toBe(false);
    expect(buttons.map((button) => button.text())).toEqual([
      "连接",
      "功能",
      "外观",
      "通知",
      "实验性",
    ]);
    expect(buttons[0].attributes("aria-current")).toBe("true");

    await buttons[2].trigger("click");
    expect(buttons[2].attributes("aria-current")).toBe("true");
  });

  it("设置项采用紧凑单行，并为短字段保留两列重排结构", async () => {
    const wrapper = mount(SettingsPage, {
      props: {
        gateway: configGateway([
          { key: "server", value: "vpn.ecnu.edu.cn" },
          { key: "username", value: "tomli" },
          { key: "routes", value: "10.0.0.0/8" },
        ]),
        appearance: appearance(),
      },
    });
    await flushPromises();

    expect(wrapper.find(".settings-fields-grid").exists()).toBe(true);
    expect(wrapper.findAll(".settings-row--dense").length).toBeGreaterThan(0);
    expect(wrapper.find(".settings-row--wide").exists()).toBe(true);
    expect(readFileSync("src/components/SettingsRow.vue", "utf8")).toContain("min-height: 48px");
    expect(readFileSync("src/pages/SettingsPage.vue", "utf8")).toContain("grid-template-columns: repeat(auto-fit, minmax(min(100%, 480px), 1fr))");
  });

  it("路由行显示条目数与修改按钮，不再渲染文本输入", async () => {
    const gateway = configGateway([{ key: "routes", value: "10.0.0.0/8,192.168.0.0/16" }]);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    expect(wrapper.get('[data-testid="routes-summary"]').text()).toBe("2 条路由");
    expect(wrapper.get('[data-testid="routes-edit"]').text()).toBe("修改");
    expect(wrapper.find('[data-testid="input-routes"]').exists()).toBe(false);
  });

  it("点修改打开路由模态；保存立即提交 configSet，不经 saveAll 且不进入脏状态", async () => {
    const gateway = configGateway([{ key: "routes", value: "10.0.0.0/8" }]);
    const wrapper = mountSettings(gateway);
    await flushPromises();
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);

    await wrapper.get('[data-testid="routes-edit"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="routes-modal"]').exists()).toBe(true);

    await wrapper.get('[data-testid="routes-add-input"]').setValue("10.1.0.0/16");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();
    await wrapper.get('[data-testid="routes-save"]').trigger("click");
    await flushPromises();

    // 立即单独提交（不经 saveAll）：configSet 仅一次、只带 routes 键。
    expect(gateway.configSet).toHaveBeenCalledTimes(1);
    expect(gateway.configSet).toHaveBeenCalledWith([{ key: "routes", value: "10.0.0.0/8,10.1.0.0/16" }]);
    expect(wrapper.find('[data-testid="routes-modal"]').exists()).toBe(false);
    // 保存不产生设置页脏状态 → 无「保存设置」入口。
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
    // 路由行条目数同步更新。
    expect(wrapper.get('[data-testid="routes-summary"]').text()).toBe("2 条路由");
  });

  it("路由模态保存失败时 toast 报错且路由行保留旧值", async () => {
    const gateway = configGateway([{ key: "routes", value: "10.0.0.0/8" }], false);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    await wrapper.get('[data-testid="routes-edit"]').trigger("click");
    await flushPromises();
    await wrapper.get('[data-testid="routes-add-input"]').setValue("10.1.0.0/16");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();
    await wrapper.get('[data-testid="routes-save"]').trigger("click");
    await flushPromises();

    expect(gateway.configSet).toHaveBeenCalledWith([{ key: "routes", value: "10.0.0.0/8,10.1.0.0/16" }]);
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("路由保存失败"))).toBe(true);
    expect(wrapper.get('[data-testid="routes-summary"]').text()).toBe("1 条路由");
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
  });

  it("服务分区独立且服务标题只出现一次", async () => {
    const runtime: ProductRuntime = {
      source: "mock",
      state: ref(present(snapshotIdle({ service_status: { installed: false, state: "stopped" } }), 61_000)),
      start: async () => undefined,
      connect: async () => undefined,
      stop: async () => undefined,
      triggerLatencyRefresh: async () => undefined,
      serviceControl: async () => ({ service_status: null, ok: true, message: "ok" }),
      dispose: () => undefined,
    };
    const wrapper = mount(SettingsPage, {
      props: { gateway: configGateway([]), appearance: appearance() },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: runtime } },
    });
    await flushPromises();

    expect(wrapper.get('[data-testid="settings-connection"]').find('[data-testid="settings-service"]').exists()).toBe(false);
    expect(wrapper.findAll('[data-testid="settings-service"]')).toHaveLength(1);
    expect(wrapper.findAll('#service-panel-title')).toHaveLength(1);
  });

  it("外观设置复用标题栏的主题、强调色和减少动效状态", async () => {
    const localAppearance = appearance();
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: localAppearance } });
    await flushPromises();

    expect(wrapper.get('[data-testid="appearance-theme"]')).toBeTruthy();
    expect(wrapper.get('[data-testid="appearance-motion"]')).toBeTruthy();
    expect(wrapper.findAll('[data-testid^="appearance-accent-"]')).toHaveLength(4);

    await wrapper.get('[data-testid="appearance-accent-violet"]').trigger("click");
    expect(localAppearance.state.value.accent).toBe("violet");
    await wrapper.get('[data-testid="appearance-motion"]').setValue("reduced");
    expect(localAppearance.state.value.motion).toBe("reduced");
  });

  it("自动重连「未实现」占位已摘除：无 Core 数据时不渲染占位行", async () => {
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: appearance() } });
    await flushPromises();

    // 占位行与「未实现」文案彻底移除（替换为真实设置项）。
    expect(wrapper.find('[data-testid="unimplemented-reconnect"]').exists()).toBe(false);
    expect(wrapper.find(".settings-capability-grid").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("DTLS");
  });

  it("自动重连并入连接分区：关闭时隐藏次数，开启后显示 type=number 并随保存批量提交", async () => {
    const gateway = configGateway([
      { key: "auto_reconnect", value: "false" },
      { key: "auto_reconnect_max_attempts", value: "0" },
    ]);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    const connection = wrapper.get('[data-testid="settings-connection"]');
    expect(connection.get('[data-testid="setting-auto_reconnect"]').find('input[type="checkbox"]').exists()).toBe(true);
    expect(connection.find('[data-testid="setting-auto_reconnect_max_attempts"]').exists()).toBe(false);
    expect(connection.text()).toContain("自动重连");
    // 开关与次数渲染在连接分区，不在通知分区。
    expect(wrapper.get('[data-testid="settings-diagnostics"]').find('[data-testid="setting-auto_reconnect"]').exists()).toBe(false);

    // 联动：开关关 → 次数行隐藏；未修改时无保存入口。
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
    await wrapper.get('[data-testid="input-auto_reconnect"]').setValue(true);
    await flushPromises();
    const attempts = connection.get('[data-testid="input-auto_reconnect_max_attempts"]');
    // type=number 提供原生上下箭头；min=0 限制非负。
    expect(attempts.attributes("type")).toBe("number");
    expect(attempts.attributes("min")).toBe("0");
    expect(
      (connection.get('[data-testid="input-auto_reconnect_max_attempts"]').element as HTMLInputElement).disabled,
    ).toBe(false);

    // 开关开→开、次数 0→5：手填保留并出现保存入口。
    await wrapper.get('[data-testid="input-auto_reconnect_max_attempts"]').setValue("5");
    await flushPromises();
    expect(
      (connection.get('[data-testid="input-auto_reconnect_max_attempts"]').element as HTMLInputElement).value,
    ).toBe("5");
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);

    // 批量提交：两项走同一次 configSet。
    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();
    expect(gateway.configSet).toHaveBeenCalledWith([
      { key: "auto_reconnect", value: "true" },
      { key: "auto_reconnect_max_attempts", value: "5" },
    ]);
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("设置已保存"))).toBe(true);
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
  });

  it("功能分区不显示保存提示幽灵文本", async () => {
    const wrapper = mountSettings(configGateway([]));
    await flushPromises();

    expect(wrapper.text()).not.toContain("以下设置需点击右上角「保存设置」后生效。");
  });

  it("自动重连次数输入非法值：内联反馈且不提交", async () => {
    const gateway = configGateway([
      { key: "auto_reconnect", value: "true" },
      { key: "auto_reconnect_max_attempts", value: "0" },
    ]);
    const wrapper = mountSettings(gateway);
    await flushPromises();

    await wrapper.get('[data-testid="input-auto_reconnect_max_attempts"]').setValue("2000");
    await flushPromises();
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);

    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();

    // 校验失败：内联反馈、不提交、不显示已保存。
    expect(wrapper.get('[data-testid="feedback-auto_reconnect_max_attempts"]').text()).toContain("0-1024");
    expect(gateway.configSet).not.toHaveBeenCalled();
    expect(wrapper.findAll('[data-testid="toast"]').some((t) => t.text().includes("已保存"))).toBe(false);
  });

  it("设置轴和页面在窄窗口下保留可用内容，并提供减少动效规则", () => {
    const pageSource = readFileSync("src/pages/SettingsPage.vue", "utf8");
    const axisSource = readFileSync("src/components/SettingsSectionAxis.vue", "utf8");
    expect(pageSource).toContain("@media (max-width: 760px)");
    expect(pageSource).toContain("grid-template-columns: 1fr");
    expect(axisSource).toContain("aria-current");
    expect(axisSource).toContain("motion-reduced");
  });

  it("设置轴为旧 C++ 形态：每个锚点图标常显、无活动膨胀块、当前分区高亮", () => {
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: appearance() } });
    const axis = wrapper.get('[data-testid="settings-section-axis"]');

    expect(axis.find(".settings-axis__marker").exists()).toBe(false);
    expect(axis.find('[data-testid="settings-axis-active-bulge"]').exists()).toBe(false);
    const buttons = axis.findAll("button");
    expect(buttons).toHaveLength(5);
    for (const button of buttons) expect(button.find("svg").exists()).toBe(true);
    expect(buttons[0].classes()).toContain("settings-axis__item--active");
    expect(readFileSync("src/components/SettingsSectionAxis.vue", "utf8")).toContain("prefers-reduced-motion");
    expect(readFileSync("src/components/SettingsSectionAxis.vue", "utf8")).toContain("@media (max-width: 760px)");
  });

  it("F1 布局：锚点轴 fixed 悬浮不占 grid 列，页头为静态横条，滚动条隐藏，左侧栏拓宽约 10%", () => {
    const pageSource = readFileSync("src/pages/SettingsPage.vue", "utf8");
    const axisSource = readFileSync("src/components/SettingsSectionAxis.vue", "utf8");
    const logsSource = readFileSync("src/pages/LogsPage.vue", "utf8");
    const shell = readFileSync("src/styles/ui-first-shell.css", "utf8");

    // R2：锚点轴固定悬浮（fixed）、不占 grid 列；设置页 grid 改为单列，去掉第二列槽位。
    expect(axisSource).toContain("position: fixed");
    expect(axisSource).not.toContain("position: sticky");
    expect(pageSource).toContain("grid-template-columns: minmax(0, 1fr);");
    expect(pageSource).not.toContain("minmax(48px, 56px)");
    expect(pageSource).not.toContain("minmax(44px, 52px)");

    // 页头为静态顶部横条（非 sticky 悬浮，无圆角无缝隙）；.content 上下内边距已取消，
    // 页根不再用负 margin 爬升（banner 落在 .content 顶部，头部不被 overflow 裁剪）。
    expect(pageSource).toContain("margin-top: 0;");
    expect(pageSource).toContain("--settings-header-height");
    // 页头不再 sticky：断言其样式块不含 position: sticky（设置/日志均改静态横条）。
    expect(pageSource).not.toMatch(/\.settings-page__header \{[\s\S]*?position: sticky/s);
    expect(logsSource).not.toMatch(/\.logs-page__header \{[\s\S]*?position: sticky/s);
    expect(logsSource).toContain("margin-top: 0;");
    expect(pageSource).not.toMatch(/calc\(-2 \* var\(--space-6\)/);
    // 目标 main（.product-content）只保留左右安全间距，上下内边距由页面内部管理。
    expect(shell).toContain("padding: 0 var(--space-6);");
    expect(shell).toContain("padding: 0 var(--space-4);");
    // 锚点轴整体右移 12px（right = var(--space-5) - 12px；增大 right 实际向左移，方向必须为减）。
    expect(axisSource).toContain("right: calc(var(--space-5) - 12px);");

    // R2：滚动容器隐藏原生滚动条但保留滚动功能。
    expect(shell).toContain("scrollbar-width: none");
    expect(shell).toMatch(/::-webkit-scrollbar\s*{[^}]*display:\s*none/s);

    // R3：左侧栏在当前尺寸基础上拓宽约 10%，并为实验卡片容器保留底部间距。
    expect(shell).toContain("clamp(212px, 23vw, 282px)");
    expect(shell).toContain("width: 194px");
    expect(pageSource).toMatch(
      /\.settings-page__content\s*\{[\s\S]*?padding-bottom:\s*var\(--space-4\);/,
    );
  });

  it("F1 布局：设置轴展开为紧凑横向胶囊，文字在 icon 左侧且纵向高度不膨胀", () => {
    const axisSource = readFileSync("src/components/SettingsSectionAxis.vue", "utf8");
    // 宽度是胶囊的横向尺寸；纵向轨道的 flex-basis 必须保持 32px，不能把节点撑成圆。
    expect(axisSource).toContain("width: 76px");
    expect(axisSource).toContain("max-width: 76px");
    expect(axisSource).toMatch(
      /\.settings-axis__item--expanded \{[\s\S]*?height:\s*32px[\s\S]*?max-height:\s*32px[\s\S]*?flex:\s*0 0 32px/,
    );
    expect(axisSource).not.toContain("flex: 0 0 246px");
    expect(axisSource).toContain("gap: 6px");
    expect(axisSource).toContain("text-align: left");
    // DOM 顺序直接表达“文字在左、icon 在右”，避免依赖 row-reverse 扭曲布局含义。
    expect(axisSource.indexOf('class="settings-axis__label"')).toBeLessThan(
      axisSource.indexOf('class="settings-axis__icon"'),
    );
    // 锚点切换飞行小球（对齐旧 C++）：orb 元素 + from→to 关键帧动画。
    expect(axisSource).toContain("axis-flight-orb");
    expect(axisSource).toContain("@keyframes axis-flight");
    expect(axisSource).toContain("--axis-flight-from");
    expect(axisSource).toContain("--axis-flight-to");
  });

  it("锚点轴命中时把滚轮转发给设置滚动容器，飞行球始终位于目标锚点下层", async () => {
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: appearance() } });
    await flushPromises();

    const layout = wrapper.get(".settings-page__layout").element as HTMLElement;
    const button = wrapper.get('[data-testid="settings-section-axis"] button');
    button.element.dispatchEvent(new WheelEvent("wheel", { bubbles: true, cancelable: true, deltaY: 96 }));
    expect(layout.scrollTop).toBe(96);

    const axisSource = readFileSync("src/components/SettingsSectionAxis.vue", "utf8");
    expect(axisSource).toContain('@wheel="forwardWheel"');
    expect(axisSource).toMatch(/\.settings-axis\s*\{[\s\S]*?pointer-events:\s*none;/);
    expect(axisSource).toMatch(/\.settings-axis__item\s*\{[\s\S]*?pointer-events:\s*auto;/);
    expect(axisSource).toMatch(/\.axis-flight-orb\s*\{[\s\S]*?z-index:\s*0;/);
    wrapper.unmount();
  });

  it("设置标题与其他页面共用页面起点的顶部留白，关闭行为下拉局部加宽且普通选项保持紧凑", async () => {
    const settingsSource = readFileSync("src/pages/SettingsPage.vue", "utf8");
    const logsSource = readFileSync("src/pages/LogsPage.vue", "utf8");
    const aboutSource = readFileSync("src/pages/AboutPage.vue", "utf8");
    const connectionSource = readFileSync("src/components/ProductConnectionHero.vue", "utf8");
    const tokensSource = readFileSync("src/styles/tokens.css", "utf8");

    expect(tokensSource).toContain("--product-page-top-gap: calc(2 * var(--space-5));");
    expect(settingsSource).toMatch(
      /\.settings-page\s*\{[^}]*padding-top:\s*var\(--product-page-top-gap\);/,
    );
    expect(settingsSource).not.toMatch(
      /\.settings-page__layout\s*\{[^}]*padding-top:\s*var\(--product-page-top-gap\);/,
    );
    expect(logsSource).toContain("padding: var(--product-page-top-gap) 0 var(--space-4);");
    expect(aboutSource).toContain("margin-top: var(--product-page-top-gap);");
    expect(connectionSource).toContain("margin-top: var(--product-page-top-gap);");
    const wrapper = mountSettings(configGateway([{ key: "server", value: "vpn-cn.ecnu.edu.cn" }]));
    document.body.append(wrapper.element);
    await flushPromises();

    const closePreference = wrapper.get('[data-testid="ui-pref-close_preference"]');
    const serverPreference = wrapper.get('[data-testid="input-server"]');
    const theme = wrapper.get('[data-testid="appearance-theme"]');
    const closePreferenceStyle = getComputedStyle(closePreference.element);
    const serverPreferenceStyle = getComputedStyle(serverPreference.element);

    expect(closePreferenceStyle.width).toBe("208px");
    expect(closePreferenceStyle.flexBasis).toBe("208px");
    // VPN 服务器与关闭行为下拉必须共用 208px 尺寸，避免宽屏/窄屏中出现对不齐。
    expect(serverPreferenceStyle.width).toBe(closePreferenceStyle.width);
    expect(serverPreferenceStyle.flexBasis).toBe(closePreferenceStyle.flexBasis);
    expect(getComputedStyle(theme.element).width).toBe("160px");
    const closePreferenceControls = wrapper.findAll(".settings-close-preference");
    expect(closePreferenceControls).toHaveLength(1);
    expect(closePreferenceControls[0].attributes("data-testid")).toBe("ui-pref-close_preference");
    const serverPreferenceControls = wrapper.findAll(".settings-server-preference");
    expect(serverPreferenceControls).toHaveLength(1);
    expect(serverPreferenceControls[0].attributes("data-testid")).toBe("input-server");
    wrapper.unmount();
  });

  it("设置项网格不使用相邻兄弟上边框，避免双列第二列首行与区块线重叠", () => {
    const rowSource = readFileSync("src/components/SettingsRow.vue", "utf8");
    const pageSource = readFileSync("src/pages/SettingsPage.vue", "utf8");

    // .settings-row + .settings-row 会按 DOM 相邻关系命中第二列第一行，
    // 不能表达 CSS Grid 的“同一视觉行”，因此不能再用它画分隔线。
    expect(rowSource).not.toContain(".settings-row + .settings-row");
    expect(pageSource).toContain(".settings-fields-grid { display: grid;");
    expect(pageSource).toContain("row-gap: var(--space-2)");
    expect(pageSource).not.toContain(".settings-fields-grid--static { row-gap: 0; }");
  });

  it("滚动位置判定：分区滑过检测线更新锚点，滚动到底强制激活最后分区", async () => {
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: appearance() } });
    await flushPromises();

    // 两分区后内容在 .settings-page__layout 内滚动；用可控测量模拟滚动。
    const container = wrapper.get('[data-testid="settings-page-layout"]').element as HTMLElement;
    const bases: Record<string, number> = {
      connection: 80,
      startup: 280,
      appearance: 480,
      diagnostics: 680,
      experimental: 880,
    };

    // 保存共享 DOM 上的原始实现，测试结束恢复，避免污染后续用例（尤其旧 pending rAF）。
    const originalContainerRect = container.getBoundingClientRect;
    const originalRects = new Map<string, () => DOMRect>();
    for (const id of Object.keys(bases)) {
      const element = wrapper.get(`[data-testid="settings-${id}"]`).element as HTMLElement;
      originalRects.set(id, element.getBoundingClientRect);
    }
    const originalOwn = new Map<string, PropertyDescriptor | undefined>();
    for (const key of ["clientHeight", "scrollHeight", "scrollTop"]) {
      originalOwn.set(key, Object.getOwnPropertyDescriptor(container, key));
    }

    try {
      container.getBoundingClientRect = () => ({ top: 0 }) as DOMRect;
      for (const [id, base] of Object.entries(bases)) {
        const element = wrapper.get(`[data-testid="settings-${id}"]`).element as HTMLElement;
        element.getBoundingClientRect = () => ({ top: base - container.scrollTop }) as DOMRect;
      }
      Object.defineProperty(container, "clientHeight", { configurable: true, value: 700 });
      Object.defineProperty(container, "scrollHeight", { configurable: true, value: 1400 });
      Object.defineProperty(container, "scrollTop", { configurable: true, writable: true, value: 0 });

      const axis = wrapper.get('[data-testid="settings-section-axis"]');
      const activeIndex = () =>
        axis.findAll("button").findIndex((button) => button.attributes("aria-current") === "true");

      // 未滚动：连接。
      container.dispatchEvent(new Event("scroll"));
      await nextTick();
      expect(activeIndex()).toBe(0);

      // 滚过「功能」分区检测线：功能激活。
      container.scrollTop = 250;
      container.dispatchEvent(new Event("scroll"));
      await nextTick();
      expect(activeIndex()).toBe(1);

      // 滚动到底：实验性必激活（短内容分区也能命中）。
      container.scrollTop = 700;
      container.dispatchEvent(new Event("scroll"));
      await nextTick();
      expect(activeIndex()).toBe(4);
    } finally {
      container.getBoundingClientRect = originalContainerRect;
      for (const [id, rect] of originalRects) {
        wrapper.get(`[data-testid="settings-${id}"]`).element.getBoundingClientRect = rect;
      }
      for (const [key, descriptor] of originalOwn) {
        if (descriptor) Object.defineProperty(container, key, descriptor);
        else delete (container as unknown as Record<string, unknown>)[key];
      }
    }
  });

  it("激活分区时短暂展开其文字，约 2s 后自动收起但保持高亮", async () => {
    const wrapper = mount(SettingsPage, { props: { gateway: configGateway([]), appearance: appearance() } });
    await flushPromises();
    const buttons = () => wrapper.get('[data-testid="settings-section-axis"]').findAll("button");

    // 挂载即激活连接分区：文字展开。
    expect(buttons()[0].classes()).toContain("settings-axis__item--expanded");

    // 真实计时器下挂载完成后，再启用假计时器控制收起（flushPromises 依赖 setTimeout）。
    vi.useFakeTimers();
    try {
      await buttons()[2].trigger("click");
      // 切换分区先走 200ms 飞行小球动画，落位后才展开文字（对齐 C++ 版本）。
      await vi.advanceTimersByTimeAsync(200);
      await nextTick();
      expect(buttons()[2].classes()).toContain("settings-axis__item--expanded");
      expect(buttons()[0].classes()).not.toContain("settings-axis__item--expanded");

      await vi.advanceTimersByTimeAsync(2000);
      await nextTick();
      expect(buttons()[2].classes()).not.toContain("settings-axis__item--expanded");
      // 收起后仍保持当前分区高亮。
      expect(buttons()[2].classes()).toContain("settings-axis__item--active");
    } finally {
      vi.useRealTimers();
    }
  });

  it("可从应用注入取得预览用的核心配置网关", async () => {
    const gateway = configGateway([{ key: "server", value: "preview.example" }]);
    const localAppearance = appearance();
    const wrapper = mount(SettingsPage, {
      global: {
        provide: {
          [APPEARANCE_KEY as symbol]: localAppearance,
          [CORE_CONFIG_GATEWAY_KEY as symbol]: gateway,
        },
      },
    });
    await flushPromises();

    expect(wrapper.get('[data-testid="setting-server"]').find("select").exists()).toBe(true);
    expect(wrapper.get('[data-testid="setting-server"]').find('[data-testid="input-server-custom"]').exists()).toBe(true);
    expect(gateway.configGet).toHaveBeenCalledOnce();
  });

  it("注入运行时时展示服务控制区，未安装状态提供安装按钮并可触发安装", async () => {
    const gateway = configGateway([]);
    const serviceControl = vi.fn(
      async (_action: ServiceControlAction): Promise<ServiceControlReply> => ({
        service_status: null,
        ok: true,
        message: "ok",
      }),
    );
    const state = present(
      snapshotIdle({ service_status: { installed: false, state: "stopped" } }),
      61_000,
    );
    const runtime: ProductRuntime = {
      source: "mock",
      state: ref(state),
      start: async () => undefined,
      connect: async () => undefined,
      stop: async () => undefined,
      triggerLatencyRefresh: async () => undefined,
      serviceControl,
      dispose: () => undefined,
    };
    const wrapper = mount(SettingsPage, {
      props: { gateway, appearance: appearance() },
      global: {
        provide: {
          [PRODUCT_RUNTIME_KEY as symbol]: runtime,
        },
      },
    });
    await flushPromises();

    const section = wrapper.get('[data-testid="settings-service"]');
    expect(section.get('[data-testid="service-status"]').text()).toBe("未安装");
    // 设置页服务区按状态渲染：未安装时提供安装按钮；连接页专属 checkbox 隐藏。
    expect(section.find('[data-testid="service-install"]').exists()).toBe(true);
    expect(section.find('[data-testid="service-auto-install-option"]').exists()).toBe(false);
    expect(section.find('[data-testid="service-repair"]').exists()).toBe(false);
    expect(section.find('[data-testid="service-uninstall"]').exists()).toBe(false);
    // 挂载时组件主动 query 一次（服务感知修复）；无用户变更动作。
    expect(serviceControl).toHaveBeenCalledTimes(1);
    expect(serviceControl).toHaveBeenCalledWith("query");
  });

  it("注入运行时展示运行中服务：仅卸载按钮，无修复/启动与连接模式，不展示二进制路径", async () => {
    const gateway = configGateway([]);
    const state = present(
      snapshotIdle({
        service_status: { installed: true, state: "running" },
      }),
      61_000,
    );
    const runtime: ProductRuntime = {
      source: "mock",
      state: ref(state),
      start: async () => undefined,
      connect: async () => undefined,
      stop: async () => undefined,
      triggerLatencyRefresh: async () => undefined,
      serviceControl: async () => ({ service_status: null, ok: true, message: "ok" }),
      dispose: () => undefined,
    };
    const wrapper = mount(SettingsPage, {
      props: { gateway, appearance: appearance() },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: runtime } },
    });
    await flushPromises();

    const section = wrapper.get('[data-testid="settings-service"]');
    expect(section.get('[data-testid="service-status"]').text()).toBe("运行中");
    // 正常运行中的服务只需卸载；不显示修复/启动/停止。
    expect(section.find('[data-testid="service-repair"]').exists()).toBe(false);
    expect(section.find('[data-testid="service-start"]').exists()).toBe(false);
    expect(section.find('[data-testid="service-uninstall"]').exists()).toBe(true);
    expect(section.text()).not.toContain("停止");
    // 设置服务卡不再展示连接模式。
    expect(section.find('[data-testid="service-mode"]').exists()).toBe(false);
    // R1：服务二进制路径已从 UI 永久摘除。
    expect(section.find('[data-testid="service-binary-path"]').exists()).toBe(false);
    expect(section.text()).not.toContain("二进制路径");
  });

  it("未注入运行时时服务区提示不可用", async () => {
    const wrapper = mount(SettingsPage, {
      props: { gateway: configGateway([]), appearance: appearance() },
    });
    await flushPromises();

    expect(wrapper.get('[data-testid="settings-service"]').text()).toContain("运行时不可用");
  });
});

describe("设置页 · 前端自有偏好", () => {
  beforeEach(() => {
    clearToasts();
    resetSettingsState();
    resetUiPrefsState();
    provideUiPrefsGateway(memoryUiPrefsGateway());
  });

  function memoryUiPrefsGateway(store: Record<string, unknown> = {}) {
    return {
      get: vi.fn(async () => ({ ...store })),
      set: vi.fn(async (patch: Record<string, unknown>) => {
        Object.assign(store, patch);
        return { ...patch };
      }),
      setAutostart: vi.fn(async (enabled: boolean) => {
        store.__autostart = enabled;
        return { ok: true };
      }),
    };
  }

  it("偏好修改先进草稿，点「保存设置」才分流应用（不经 core 配置网关）", async () => {
    const gateway = configGateway([]);
    const uiGateway = memoryUiPrefsGateway();
    provideUiPrefsGateway(uiGateway);
    const wrapper = mount(SettingsPage, { props: { gateway, appearance: appearance() } });
    await flushPromises();

    // 编辑阶段：不触发任何网关写。
    await wrapper.get('[data-testid="ui-pref-launch_at_login"]').setValue();
    await wrapper.get('[data-testid="ui-pref-connect_notify"]').setValue();
    const closeSelect = wrapper.get('[data-testid="ui-pref-close_preference"]');
    await closeSelect.setValue("quit");
    await flushPromises();
    expect(uiGateway.set).not.toHaveBeenCalled();
    expect(uiGateway.setAutostart).not.toHaveBeenCalled();
    // 脏 → 出现保存按钮。
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(true);

    // 保存：注册表 + 偏好文件各一次；core 配置零调用。
    await wrapper.get('[data-testid="save-all-settings"]').trigger("click");
    await flushPromises();
    expect(uiGateway.setAutostart).toHaveBeenCalledWith(true);
    expect(uiGateway.set).toHaveBeenCalledWith(
      expect.objectContaining({ close_preference: "quit", connect_notify: true }),
    );
    expect(gateway.configSet).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="save-all-settings"]').exists()).toBe(false);
  });

  it("通知分区渲染四个独立开关（data-testid 齐备，重连项带生效说明）", async () => {
    resetUiPrefsState();
    provideUiPrefsGateway(
      memoryUiPrefsGateway({
        connect_notify: true,
        suppress_notify_when_foreground: true,
      }),
    );
    const wrapper = mountSettings(configGateway([]));
    await flushPromises();

    const section = wrapper.get('[data-testid="settings-diagnostics"]');
    for (const testid of [
      "ui-pref-connect_notify",
      "ui-pref-disconnect_notify",
      "ui-pref-reconnect_notify",
      "ui-pref-suppress_notify_when_foreground",
    ]) {
      expect(section.find(`[data-testid="${testid}"]`).exists()).toBe(true);
    }

    // 重连开关的说明文字：仅在开启自动重连后真正生效。
    expect(section.text()).toContain("仅在开启自动重连后真正生效");
    // 前台抑制默认开（注入 true 时控件勾选）。
    expect(
      (section.get('[data-testid="ui-pref-suppress_notify_when_foreground"]')
        .element as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (section.get('[data-testid="ui-pref-connect_notify"]').element as HTMLInputElement).checked,
    ).toBe(true);
    // 旧单开关不再渲染。
    expect(section.find('[data-testid="ui-pref-connection_state_notifications"]').exists()).toBe(
      false,
    );
  });

  it("注入的偏好值反映在控件初始状态；改名与删行按规呈现", async () => {
    resetUiPrefsState();
    provideUiPrefsGateway(
      memoryUiPrefsGateway({ silent_startup: true, minimize_to_tray_on_connect: true }),
    );
    const wrapper = mount(SettingsPage, {
      props: { gateway: configGateway([]), appearance: appearance() },
    });
    await flushPromises();

    expect(
      (wrapper.get('[data-testid="ui-pref-silent_startup"]').element as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (wrapper.get('[data-testid="ui-pref-minimize_to_tray_on_connect"]')
        .element as HTMLInputElement).checked,
    ).toBe(true);

    // 关闭行为下拉含改名后的「智能判断最小化与退出」。
    const closeOptions = wrapper.get('[data-testid="ui-pref-close_preference"]').findAll("option");
    expect(closeOptions.map((o) => o.text())).toEqual([
      "智能判断最小化与退出",
      "最小化到托盘",
      "直接退出",
    ]);

    // 实验性分栏存在并带推荐维持默认提示；窗口模式/诊断日志行已删除。
    expect(wrapper.find('[data-testid="settings-experimental"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="experimental-notice"]').text()).toContain("推荐维持默认");
    expect(wrapper.find('[data-testid="input-mtu"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="input-user_agent"]').exists()).toBe(true);
    expect(wrapper.text()).not.toContain("窗口模式");
    expect(wrapper.text()).not.toContain("诊断日志");
    // MTU/User-Agent 不再出现在连接与网络栏（只在实验性栏）。
    expect(wrapper.find('[data-testid="setting-mtu"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="setting-user_agent"]').exists()).toBe(false);
  });

  it("设置服务卡：无连接模式段，已安装未运行显示修复+卸载，无二进制路径", async () => {
    const state = present(
      snapshotIdle({
        service_status: {
          installed: true,
          state: "stopped",
        },
      }),
      61_000,
    );
    const runtime: ProductRuntime = {
      source: "mock",
      state: ref(state),
      start: async () => undefined,
      connect: async () => undefined,
      stop: async () => undefined,
      triggerLatencyRefresh: async () => undefined,
      serviceControl: async () => ({ service_status: null, ok: true, message: "ok" }),
      dispose: () => undefined,
    };
    const wrapper = mount(SettingsPage, {
      props: { gateway: configGateway([]), appearance: appearance() },
      global: { provide: { [PRODUCT_RUNTIME_KEY as symbol]: runtime } },
    });
    await flushPromises();

    const panel = wrapper.get('[data-testid="settings-service-control"]');
    expect(panel.get('[data-testid="service-status"]').text()).toBe("已停止");
    // 无连接模式段（服务/一次性/自动均不再展示）。
    expect(panel.find('[data-testid="service-mode"]').exists()).toBe(false);
    expect(panel.findAll(".mode-segment__item")).toHaveLength(0);
    // 已安装未运行：修复 + 卸载；无启动按钮。
    expect(panel.findAll(".service-actions button").map((b) => b.text())).toEqual(["修复", "卸载"]);
    expect(panel.find('[data-testid="service-binary-path"]').exists()).toBe(false);
  });
});
