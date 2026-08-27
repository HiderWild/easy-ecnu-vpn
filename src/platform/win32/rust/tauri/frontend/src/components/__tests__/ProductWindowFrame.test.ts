import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { ref } from "vue";
import ProductWindowFrame from "../ProductWindowFrame.vue";
import ProductRail from "../ProductRail.vue";
import type { Appearance } from "../../product/appearance";
import type { WindowChromePort } from "../../product/window-chrome";

// 原始 CSS 文本：在测试里复现 main.ts 的全局样式级联
// （base.css 的全局 button{min-height:36px} + ui-first-shell.css），
// 供 getComputedStyle 断言标题栏按钮组是否收敛在 34px 标题栏内。
const titlebarCss = (): string =>
  `${readFileSync(resolve(process.cwd(), "src/styles/base.css"), "utf8")}\n${readFileSync(
    resolve(process.cwd(), "src/styles/ui-first-shell.css"),
    "utf8",
  )}`;
function appearance(): Appearance { return { state: ref({ theme: "system", accent: "azure", motion: "normal", mode: "advanced" }), documentClass: ref(""), setTheme: vi.fn(), setAccent: vi.fn(), setMotion: vi.fn(), setMode: vi.fn(), applyDocument: vi.fn() } as unknown as Appearance; }
function chrome(): WindowChromePort { return { setMode: vi.fn(async () => undefined), control: vi.fn(async () => undefined), setVisible: vi.fn(async () => undefined), subscribeControlState: vi.fn(async () => () => undefined) }; }
describe("ProductWindowFrame", () => {
  const baseProps = (mode: "advanced" | "minimal") => ({ mode, chrome: chrome(), appearance: appearance(), currentPage: "connect" });
  it("advanced titlebar has no branding; rail has branding", () => { const w = mount(ProductWindowFrame, { props: baseProps("advanced") }); expect(w.get('[data-testid="product-titlebar"]').text()).not.toContain("EXV"); expect(w.get('[data-testid="product-rail"]').text()).toContain("EXV"); expect(w.get('[data-testid="product-rail"]').text()).toContain("for ECNU"); });
  it("minimal titlebar has only EXV and content has no branding", () => { const w = mount(ProductWindowFrame, { props: baseProps("minimal") }); expect(w.get('[data-testid="product-titlebar"]').text()).toContain("EXV"); expect(w.get('[data-testid="product-titlebar"]').text()).not.toContain("for ECNU"); expect(w.get('[data-testid="product-content"]').text()).not.toContain("for ECNU"); expect(w.get('[data-testid="product-content"]').text()).not.toContain("EXV"); });
  it("minimal brand 收窄图标与文字间距，并将左侧边距减半", () => {
    const shell = readFileSync(resolve(process.cwd(), "src/styles/ui-first-shell.css"), "utf8");

    expect(shell).toContain(".minimal-brand {");
    expect(shell).toContain("gap: var(--space-1);");
    expect(shell).toContain("padding-left: calc(var(--space-3) / 2);");
    expect(shell).toMatch(/\.minimal-brand img\s*\{[^}]*width:\s*20px;[^}]*height:\s*20px;/);
  });
  it("advanced 左侧栏在当前宽度基础上拓宽约 10%", () => {
    const shell = readFileSync(resolve(process.cwd(), "src/styles/ui-first-shell.css"), "utf8");

    expect(shell).toContain("width: clamp(212px, 23vw, 282px);");
    expect(shell).toContain("width: 194px;");
  });
  it("renders both choices in the two-position mode control", () => { const advanced = mount(ProductWindowFrame, { props: baseProps("advanced") }); expect(advanced.findAll('[data-testid^="mode-option-"]')).toHaveLength(2); expect(advanced.get('[data-testid="mode-option-advanced"]').attributes("aria-pressed")).toBe("true"); expect(advanced.get('[data-testid="mode-option-minimal"]').attributes("aria-pressed")).toBe("false"); });
  it("updates appearance only after chrome mode succeeds", async () => { const app = appearance(); const port = chrome(); const w = mount(ProductWindowFrame, { props: { ...baseProps("advanced"), chrome: port, appearance: app } }); await w.get('[data-testid="mode-option-minimal"]').trigger("click"); expect(port.setMode).toHaveBeenCalledWith("minimal"); expect(app.setMode).toHaveBeenCalledWith("minimal"); vi.mocked(port.setMode).mockRejectedValueOnce(new Error("no")); await w.get('[data-testid="mode-option-minimal"]').trigger("click"); expect(app.setMode).toHaveBeenCalledTimes(1); });
  it("uses a three-position theme control and calls only Appearance", async () => { const app = appearance(); const w = mount(ProductWindowFrame, { props: { ...baseProps("advanced"), appearance: app } }); expect(w.findAll('[data-testid^="theme-option-"]')).toHaveLength(3); await w.get('[data-testid="theme-option-dark"]').trigger("click"); expect(app.setTheme).toHaveBeenCalledWith("dark"); });
  it("renders distinct native window controls and hides maximize in minimal mode", () => { const advanced = mount(ProductWindowFrame, { props: baseProps("advanced") }); expect(advanced.findAll('[data-testid^="native-window-control-"]')).toHaveLength(3); expect(advanced.get('[data-testid="native-window-control-minimize"] svg').attributes("data-icon")).toBe("minimize"); expect(advanced.get('[data-testid="native-window-control-maximize"] svg').attributes("data-icon")).toBe("maximize"); expect(advanced.get('[data-testid="native-window-control-close"] svg').attributes("data-icon")).toBe("close"); const minimal = mount(ProductWindowFrame, { props: baseProps("minimal") }); expect(minimal.find('[data-testid="native-window-control-maximize"]').exists()).toBe(false); });
  it("routes native window control clicks through the window chrome port", async () => { const port = chrome(); const w = mount(ProductWindowFrame, { props: { ...baseProps("advanced"), chrome: port } }); await w.get('[data-testid="native-window-control-minimize"]').trigger("click"); expect(port.control).toHaveBeenCalledWith("minimize"); });
  it("marks titlebar drag and non-drag control regions", () => { const w = mount(ProductWindowFrame, { props: baseProps("advanced") }); expect(w.get('[data-testid="product-titlebar"]').attributes("data-window-drag-region")).toBe("true"); expect(w.get('[data-testid="titlebar-control-region"]').attributes("data-window-control-region")).toBe("true"); });
  it("keeps the titlebar fixed and assigns scrolling only to non-connect pages", () => {
    const connect = mount(ProductWindowFrame, { props: baseProps("advanced") });
    expect(connect.get('[data-testid="product-content"]').classes()).not.toContain("product-content--scrollable");
    const settings = mount(ProductWindowFrame, { props: { ...baseProps("advanced"), currentPage: "settings" } });
    expect(settings.get('[data-testid="product-content"]').classes()).toContain("product-content--scrollable");
  });
  it("rail emits navigation for the single page state", async () => { const w = mount(ProductRail, { props: { currentPage: "connect" } }); expect(w.findAll("nav button")).toHaveLength(4); expect(w.text()).toContain("关于"); await w.get("button:nth-child(2)").trigger("click"); expect(w.emitted("navigate")?.[0]).toEqual(["logs"]); await w.get("button:nth-child(3)").trigger("click"); expect(w.emitted("navigate")?.[1]).toEqual(["settings"]); await w.get("button:nth-child(4)").trigger("click"); expect(w.emitted("navigate")?.[2]).toEqual(["about"]); });
  it("keeps the titlebar button groups inside the 34px titlebar (no vertical overflow)", () => {
    // 复现 main.ts 的全局级联：base.css（含全局 button{min-height:36px}）+ ui-first-shell.css。
    const style = document.createElement("style");
    style.textContent = titlebarCss();
    document.head.appendChild(style);

    // attachTo 挂载后 happy-dom 才能用 getComputedStyle 解析样式表规则。
    const w = mount(ProductWindowFrame, { props: baseProps("advanced"), attachTo: document.body });
    const titlebar = w.get('[data-testid="product-titlebar"]').element as HTMLElement;
    const actions = w.get('[data-testid="titlebar-control-region"]').element as HTMLElement;
    const theme = w.get('[data-testid="titlebar-theme-mode-control"]').element as HTMLElement;
    const mode = w.get('[data-testid="mode-segmented-control"]').element as HTMLElement;
    const button = w.get('[data-testid="theme-option-dark"]').element as HTMLElement;

    // 结构：两个按钮组与标题栏 actions 容器都挂在 product-titlebar 内。
    expect(titlebar.contains(actions)).toBe(true);
    expect(actions.contains(theme)).toBe(true);
    expect(actions.contains(mode)).toBe(true);

    // 按钮高度收敛为 22px，且显式 min-height 覆盖全局 button{min-height:36px}，
    // 否则按钮被撑到 36px、整组溢出 34px 标题栏上下边缘。
    expect(getComputedStyle(button).height).toBe("22px");
    expect(getComputedStyle(button).minHeight).toBe("22px");

    // 按钮组容器垂直内边距收紧为 1px、水平保持 2px。
    expect(getComputedStyle(theme).paddingTop).toBe("1px");
    expect(getComputedStyle(theme).paddingLeft).toBe("2px");

    // 边框宽度从样式表规则取值（happy-dom 对 border 的 computed 样式解析为空）。
    const groupRule = Array.from(style.sheet!.cssRules).find(
      (rule): rule is CSSStyleRule =>
        rule instanceof CSSStyleRule &&
        rule.selectorText.replace(/\s+/g, " ").includes(".mode-segmented-control") &&
        !rule.selectorText.includes("__button"),
    );
    expect(groupRule).toBeDefined();
    const borderWidth = parseFloat(groupRule!.style.getPropertyValue("border"));
    expect(borderWidth).toBe(1);

    // 总高 = 按钮 22px + 上下 padding 2px + 上下边框 2px = 26px，≤ 30px 且小于 34px 标题栏。
    const groupHeight =
      parseFloat(getComputedStyle(button).height) +
      parseFloat(getComputedStyle(theme).paddingTop) * 2 +
      borderWidth * 2;
    expect(groupHeight).toBeLessThanOrEqual(30);
    expect(groupHeight).toBeLessThan(34);
    w.unmount();
  });
});
