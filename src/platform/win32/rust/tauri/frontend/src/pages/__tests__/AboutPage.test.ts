import { readFileSync } from "node:fs";

import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";

import AboutPage from "../AboutPage.vue";
import { PRODUCT_VERSION } from "../../product/version";
import type { CoreConfigGateway } from "../../product/core-config";

function gateway(items: ReadonlyArray<{ key: string; value: string }>): CoreConfigGateway {
  return {
    configGet: async () => items,
    configSet: async () => true,
  };
}

describe("关于页（左侧栏独立入口）", () => {
  it("关于页 header 保留明确的顶部间距", () => {
    const source = readFileSync("src/pages/AboutPage.vue", "utf8");
    expect(source).toMatch(/\.about-hero\s*\{[\s\S]*?margin-top:\s*var\(--product-page-top-gap\);/);
  });

  it("展示产品身份（图标/应用名/副标题/版本/作者/仓库链接）", async () => {
    const wrapper = mount(AboutPage, { props: { gateway: gateway([]) } });
    await flushPromises();

    expect(wrapper.find(".about-logo").attributes("src")).toContain("exv-logo.svg");
    expect(wrapper.get("#about-title").text()).toBe("EXV");
    expect(wrapper.text()).toContain("for ECNU");
    // 版本来自 tauri.conf.json（构建期注入）；与 PRODUCT_VERSION 同源。
    expect(wrapper.get('[data-testid="about-version"]').text()).toBe(PRODUCT_VERSION);
    // 作者继承 C++ 产品线（distribution/ecnu.json 的 HiderWild）。
    expect(wrapper.get('[data-testid="about-author"]').text()).toBe("HiderWild");
  });

  it("展示项目仓库链接（HiderWild/exv-ecnuvpn）", async () => {
    const wrapper = mount(AboutPage, { props: { gateway: gateway([]) } });
    await flushPromises();

    const repo = wrapper.get('[data-testid="about-repository"]');
    expect(repo.text()).toBe("HiderWild/exv-ecnuvpn");
    expect(repo.attributes("href")).toBe("https://github.com/HiderWild/exv-ecnuvpn/");
  });

  it("点击项目仓库调用原生外部打开命令", async () => {
    const mockedInvoke = vi.mocked(invoke);
    mockedInvoke.mockResolvedValueOnce(undefined);
    const wrapper = mount(AboutPage, { props: { gateway: gateway([]) } });
    await flushPromises();

    await wrapper.get('[data-testid="about-repository"]').trigger("click");
    await flushPromises();
    expect(mockedInvoke).toHaveBeenCalledWith("open_external", {
      url: "https://github.com/HiderWild/exv-ecnuvpn/",
    });
  });

  it("关于页不再展示校园网 VPN Rust 产品线幽灵文案", async () => {
    const wrapper = mount(AboutPage, { props: { gateway: gateway([]) } });
    await flushPromises();

    expect(wrapper.text()).not.toContain("校园网 VPN 连接客户端（Rust 原生产品线。）");
    expect(wrapper.text()).not.toContain("校园网连接客户端（Rust 原生产品线）");
  });

  it("提供更新日志区，第一项默认展开、其余折叠", async () => {
    const wrapper = mount(AboutPage, { props: { gateway: gateway([]) } });
    await flushPromises();

    const details = wrapper.get('[data-testid="about-changelog"]');
    expect(details.text()).toContain("更新日志");
    expect(details.attributes("open")).toBeDefined();
    const entries = details.findAll("details");
    // 8 条 C++ 历史 + 1 条当前版本（4.0.0）。
    expect(entries.length).toBe(9);
    expect(entries[0].attributes("open")).toBeDefined();
    entries.slice(1).forEach((entry) => {
      expect(entry.attributes("open")).toBeUndefined();
    });
    // 当前版本（4.0.0）位于第一项。
    expect(entries[0].text()).toContain(PRODUCT_VERSION);
    expect(entries[0].text()).toContain("完全重构");
    expect(entries[0].text()).toContain("重组业务流和架构设计");
    expect(entries[0].text()).toContain("连接延迟最高降低 82%");
    // 历史归纳条目带徽标。
    const inferred = details.findAll("details").find((entry) => entry.text().includes("历史归纳"));
    expect(inferred).toBeDefined();
  });

  it("没有其它配置时不展示无含义的空状态文案", async () => {
    const wrapper = mount(AboutPage, { props: { gateway: gateway([]) } });
    await flushPromises();

    expect(wrapper.text()).not.toContain("没有其它已读取的配置");
  });

  it("未知核心键只读展示，绝不提交", async () => {
    const g = gateway([{ key: "opaque.key", value: "x" }]);
    const wrapper = mount(AboutPage, { props: { gateway: g } });
    await flushPromises();

    expect(wrapper.get('[data-testid="about-advanced"]').text()).toContain("opaque.key");
    expect(wrapper.find("input,button,select").exists()).toBe(false);
  });
});
