import { readFileSync } from "node:fs";

import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import MinimalConnectionView from "../MinimalConnectionView.vue";
import { connectionActionFor } from "../../product/connection-action";
import { present } from "../../product/presenter";
import {
  snapshotConnected,
  snapshotConnecting,
  snapshotIdle,
  snapshotFailedClean,
  snapshotFailedDirty,
  snapshotReconciling,
  snapshotStopping,
} from "../../test/fixtures";

function stateOf(snapshot: Parameters<typeof present>[0]) {
  return present(snapshot, 61_000, {
    account: "preview-user",
    vpnServer: "vpn-cn.ecnu.edu.cn",
    campusIp: "10.88.88.5",
  });
}

function mountView(snapshot: Parameters<typeof present>[0]) {
  const state = stateOf(snapshot);
  return mount(MinimalConnectionView, {
    props: { state, action: connectionActionFor(state) },
  });
}

describe("极简模式连接视图", () => {
  it("未连接显示状态、说明和连接动作，不显示统计或环境字段", () => {
    const wrapper = mountView(snapshotIdle());

    expect(wrapper.get("[data-testid='minimal-status']").text()).toContain("未连接");
    expect(wrapper.get("[data-testid='minimal-action']").text()).toBe("连接");
    expect(wrapper.find("[data-testid='minimal-traffic']").exists()).toBe(false);
    expect(wrapper.text()).not.toMatch(/TUN|系统代理|路由策略|拓扑|插头|双头箭头/);
  });

  it("连接中保留八段进度和取消动作，不显示流量", () => {
    const wrapper = mountView(snapshotConnecting("connecting_control"));

    expect(wrapper.findAll("[data-testid='minimal-progress-segment']")).toHaveLength(8);
    expect(wrapper.get("[data-testid='minimal-action']").text()).toBe("取消");
    expect(wrapper.find("[data-testid='minimal-traffic']").exists()).toBe(false);
    expect(wrapper.text()).not.toMatch(/TUN|系统代理|路由策略|拓扑|插头|双头箭头/);
  });

  it("已连接以独立紧凑摘要显示状态、在线、账户、下载/上传速率和延迟", () => {
    const wrapper = mountView(snapshotConnected({}, {
      reconnect: { auto_reconnect: true, max_attempts: 3, current_attempt: 0, active: false },
    }));

    expect(wrapper.get("[data-testid='minimal-action']").text()).toBe("断开");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("在线");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("账户");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("preview-user");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("下载");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("上传");
    expect(wrapper.find("[data-testid='minimal-traffic-summary']").exists()).toBe(true);
    expect(wrapper.get("[data-testid='minimal-traffic-summary']").text()).toContain("1 KB/s");
    expect(wrapper.get("[data-testid='minimal-traffic-summary']").text()).toContain("2 KB/s");
    expect(wrapper.find("[data-testid='traffic-metrics-panel']").exists()).toBe(false);
    expect(wrapper.find("[data-testid^='traffic-metric-']").exists()).toBe(false);
    expect(wrapper.find("[data-testid='minimal-traffic-summary'] small").exists()).toBe(false);
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("连接时延");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("24 ms");
    expect(wrapper.findAll("[data-testid='minimal-traffic-summary'] svg").map((icon) => icon.attributes("viewBox"))).toEqual([
      "0 0 24 24",
      "0 0 24 24",
    ]);
    expect(wrapper.findAll("[data-testid='minimal-traffic-summary'] svg").map((icon) => icon.findAll("path").map((path) => path.attributes("d")))).toEqual([
      ["m5 12 7-7 7 7", "M12 19V5"],
      ["M12 5v14", "m19 12-7 7-7-7"],
    ]);
    expect(wrapper.text()).not.toMatch(/TUN|系统代理|路由策略|拓扑|插头|双头箭头/);
  });

  it("未开启自动重连时不显示时延", () => {
    const wrapper = mountView(snapshotConnected());

    expect(wrapper.get("[data-testid='minimal-traffic']").text()).not.toContain("延迟");
  });

  it("已连接但统计不可用时保留连接信息并以破折号表示缺失统计", () => {
    const wrapper = mountView(snapshotConnected({}, { stats: null }));

    expect(wrapper.find("[data-testid='minimal-traffic']").exists()).toBe(true);
    expect(wrapper.find("[data-testid='minimal-traffic-summary']").exists()).toBe(true);
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("账户");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("00:01:00");
    expect(wrapper.get("[data-testid='minimal-traffic']").text()).toContain("—");
    expect(wrapper.text()).not.toMatch(/统计暂不可用|0\s*(B|KB|MB|秒)/);
  });

  it("未连接和连接中绝不显示速度、流量或在线时长", () => {
    for (const snapshot of [snapshotIdle(), snapshotConnecting("connecting_control")]) {
      const wrapper = mountView(snapshot);
      expect(wrapper.find("[data-testid='minimal-traffic']").exists()).toBe(false);
      expect(wrapper.text()).not.toMatch(/下载|上传|累计|在线时长/);
    }
  });

  it("没有真实自动重连事实时隐藏自动重连，不在正文重复 Logo", () => {
    const wrapper = mountView(snapshotConnected());

    expect(wrapper.text()).not.toContain("自动重连");
    expect(wrapper.find("[data-testid='minimal-body-logo']").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("校园网");
    expect(wrapper.text()).not.toContain("for ECNU");
  });

  it.each([
    [snapshotStopping(), "处理中"],
    [snapshotReconciling(), "取消"],
    [snapshotFailedClean(), "重试"],
    [snapshotFailedDirty(), "重试"],
  ])("%s 使用统一动作并保持清晰状态", (snapshot, label) => {
    const wrapper = mountView(snapshot);
    expect(wrapper.get("[data-testid='minimal-action']").text()).toBe(label);
    expect(wrapper.get("[data-testid='minimal-status']").text()).toBeTruthy();
  });

  it("固定尺寸、可读字号、按钮触控面积和 reduced-motion 有源代码契约", () => {
    const source = readFileSync("src/components/MinimalConnectionView.vue", "utf8");
    const shell = readFileSync("src/styles/ui-first-shell.css", "utf8");
    expect(source).toContain("data-testid=\"minimal-status\"");
    expect(source).toContain('import MinimalTrafficSummary');
    expect(source).not.toContain('import TrafficMetricsPanel');
    expect(shell).toMatch(/328px/);
    expect(shell).toMatch(/136px/);
    expect(shell).toMatch(/font-size:\s*(?:1[2-9]|[2-9]\d)px/);
    expect(shell).toMatch(/min-(?:width|height):\s*(?:7[2-9]|[89]\d)px/);
    expect(shell).toMatch(/prefers-reduced-motion/);
    expect(shell).not.toMatch(/data-tauri-drag-region/);
  });
});
