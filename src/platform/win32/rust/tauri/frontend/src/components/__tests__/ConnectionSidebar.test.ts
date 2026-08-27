import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ConnectionSidebar from "../ConnectionSidebar.vue";
import { present } from "../../product/presenter";
import { snapshotConnected } from "../../test/fixtures";

function stateOf(overrides: Parameters<typeof snapshotConnected>[1] = {}) {
  return present(
    snapshotConnected({ latency_ms: 24 }, {
      system_proxy: {
        mode: "manual",
        endpoint_count: 1,
        bypass_merged: false,
        topology: "t1",
      },
      proxy_tun: {
        detected: true,
        adapters: [],
        route_policy: "exv-before-proxy-tun",
      },
      ...overrides,
    }),
    61_000,
    {
      account: "preview-user",
      vpnServer: "vpn-cn.ecnu.edu.cn",
      campusIp: "10.88.88.5",
    },
  );
}

function mountSidebar(overrides: Parameters<typeof snapshotConnected>[1] = {}) {
  return mount(ConnectionSidebar, { props: { state: stateOf(overrides) } });
}

describe("完整模式连接侧栏", () => {
  it("用带灯的状态第一行表达已连接，不重复标题或连接状态行", () => {
    const wrapper = mountSidebar();

    expect(wrapper.get('[data-testid="connection-status-pill"]').text()).toContain("已连接");
    expect(wrapper.find('[data-testid="connection-status-row"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain("连接信息");
  });

  it("把上传下载以无卡片的两行紧凑指标放在 VPN 服务器与环境状态之间", () => {
    const wrapper = mountSidebar();

    expect(wrapper.find('[data-testid="traffic-metrics-panel"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="traffic-metric-upload"]').text()).toContain("1 KB/s");
    expect(wrapper.get('[data-testid="traffic-metric-upload"]').text()).toContain("2 KB");
    expect(wrapper.get('[data-testid="traffic-metric-download"]').text()).toContain("2 KB/s");
    expect(wrapper.get('[data-testid="traffic-metric-download"]').text()).toContain("4 KB");
    expect(wrapper.get('[data-testid="traffic-metric-upload"] svg').attributes("data-direction")).toBe("up");
    expect(wrapper.get('[data-testid="traffic-metric-download"] svg').attributes("data-direction")).toBe("down");
    expect(wrapper.text()).not.toContain("上传");
    expect(wrapper.text()).not.toContain("下载");

    const vpnServer = wrapper.get('[data-testid="connection-vpn-server"]').element;
    const traffic = wrapper.get('[data-testid="traffic-metrics-panel"]').element;
    const environment = wrapper.get('[data-testid="sidebar-environment"]').element;
    expect(vpnServer.compareDocumentPosition(traffic) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0);
    expect(traffic.compareDocumentPosition(environment) & Node.DOCUMENT_POSITION_FOLLOWING).not.toBe(0);

    const metricsSource = readFileSync(resolve(process.cwd(), "src/components/TrafficMetricsPanel.vue"), "utf8");
    expect(metricsSource).not.toMatch(/\.traffic-metric\s*\{[^}]*border\s*:/s);
    expect(metricsSource).not.toMatch(/\.traffic-metric\s*\{[^}]*border-radius\s*:/s);
    expect(metricsSource).not.toMatch(/\.traffic-metric\s*\{[^}]*background\s*:/s);
  });

  it("已连接时始终显示时延，不把统计能力错误绑到自动重连开关", () => {
    const wrapper = mountSidebar();

    expect(wrapper.get('[data-testid="connection-latency"]').text()).toContain("24 ms");
  });

  it("复用 C++ WebUI 的 Lucide 24×24 上下箭头几何，而不拉伸成长箭杆", () => {
    const wrapper = mountSidebar();
    const upload = wrapper.get('[data-testid="traffic-metric-upload"] svg');
    const download = wrapper.get('[data-testid="traffic-metric-download"] svg');

    expect(upload.attributes("viewBox")).toBe("0 0 24 24");
    expect(download.attributes("viewBox")).toBe("0 0 24 24");
    expect(upload.findAll("path").map((path) => path.attributes("d"))).toEqual([
      "m5 12 7-7 7 7",
      "M12 19V5",
    ]);
    expect(download.findAll("path").map((path) => path.attributes("d"))).toEqual([
      "M12 5v14",
      "m19 12-7 7-7-7",
    ]);
  });

  it("在侧栏底部同一行显示系统代理与 TUN 的二分状态灯", () => {
    const wrapper = mountSidebar();

    expect(wrapper.get('[data-testid="sidebar-environment"]')).toBeTruthy();
    expect(wrapper.get('[data-testid="system-proxy-status"]').attributes("data-enabled")).toBe("true");
    expect(wrapper.get('[data-testid="tun-status"]').attributes("data-enabled")).toBe("true");
    expect(wrapper.find('[data-testid="sidebar-environment-divider"]').exists()).toBe(true);

    const disabled = mountSidebar({ system_proxy: null, proxy_tun: null });
    expect(disabled.get('[data-testid="system-proxy-status"]').attributes("data-enabled")).toBe("false");
    expect(disabled.get('[data-testid="tun-status"]').attributes("data-enabled")).toBe("false");
  });

  it("按 product rail 的内联宽度而非视口宽度收窄连接信息", () => {
    const shell = readFileSync(resolve(process.cwd(), "src/styles/ui-first-shell.css"), "utf8");
    const sidebar = readFileSync(resolve(process.cwd(), "src/components/ConnectionSidebar.vue"), "utf8");

    expect(shell).toMatch(
      /\.product-rail\s*\{[^}]*container-name:\s*product-rail;[^}]*container-type:\s*inline-size;/s,
    );
    expect(sidebar).toMatch(/@container\s+product-rail\s*\(\s*max-width:\s*220px\s*\)/);
    expect(sidebar).toMatch(/grid-template-columns:\s*1fr;/);
    expect(sidebar).toMatch(/text-align:\s*left;/);
    expect(sidebar).not.toMatch(/@media\s*\(\s*max-width:\s*(?:900|560)px\s*\)/);
  });

  it("VPN 服务器在各 rail 宽度下保持单行截断，而不拆成两行", () => {
    const sidebar = readFileSync(resolve(process.cwd(), "src/components/ConnectionSidebar.vue"), "utf8");

    expect(sidebar).toMatch(/class="info-row info-row--vpn-server"/);
    expect(sidebar).toMatch(/\.info-row--vpn-server dd\s*\{[^}]*overflow:\s*hidden;[^}]*text-overflow:\s*ellipsis;[^}]*white-space:\s*nowrap;/s);
  });
});
