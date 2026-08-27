import { describe, expect, it } from "vitest";
import { mount } from "@vue/test-utils";

import ProductActionBar from "../ProductActionBar.vue";
import { present } from "../../product/presenter";
import { snapshotConnected, snapshotIdle } from "../../test/fixtures";

describe("ProductActionBar 连接环境摘要", () => {
  it("环境状态不再重复渲染在连接操作栏", () => {
    const wrapper = mount(ProductActionBar, { props: { state: present(snapshotIdle(), 0) } });
    expect(wrapper.find('[data-testid="network-environment"]').exists()).toBe(false);
    expect(wrapper.text()).not.toContain("系统代理");
    expect(wrapper.text()).not.toContain("TUN");
  });

  it("重连激活时显示「重连中（第 N 次）」与自动重连开关", () => {
    const state = present(
      snapshotConnected(
        {},
        {
          reconnect: {
            auto_reconnect: true,
            max_attempts: 5,
            current_attempt: 2,
            active: true,
          },
        },
      ),
      61_000,
    );
    const wrapper = mount(ProductActionBar, { props: { state } });

    const reconnect = wrapper.get('[data-testid="reconnect-status"]');
    expect(reconnect.text()).toContain("重连中 · 第 2 次");
  });

  it("重连仅开启（非激活）时显示已重连次数", () => {
    const state = present(
      snapshotIdle({
        reconnect: { auto_reconnect: true, max_attempts: 3, current_attempt: 0, active: false },
      }),
      0,
    );
    const wrapper = mount(ProductActionBar, { props: { state } });

    const reconnect = wrapper.get('[data-testid="reconnect-status"]');
    expect(reconnect.text()).toContain("已重连 0 次");
  });

  it("未启用也未激活重连时不渲染重连项", () => {
    const state = present(snapshotIdle(), 0);
    const wrapper = mount(ProductActionBar, { props: { state } });

    expect(wrapper.find('[data-testid="reconnect-status"]').exists()).toBe(false);
  });
});
