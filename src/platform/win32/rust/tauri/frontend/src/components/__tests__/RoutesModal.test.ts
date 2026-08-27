import { readFileSync } from "node:fs";

import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import RoutesModal from "../RoutesModal.vue";

function mountModal(routes: string[], open = true) {
  return mount(RoutesModal, { props: { routes, open } });
}

async function selectPair(wrapper: ReturnType<typeof mountModal>, a: number, b: number) {
  await wrapper.get(`[data-testid="route-select-${a}"]`).setValue(true);
  await wrapper.get(`[data-testid="route-select-${b}"]`).setValue(true);
  await flushPromises();
}

describe("路由设置模态", () => {
  it("渲染路由列表；空列表显示占位", () => {
    const wrapper = mountModal([]);
    expect(wrapper.find('[data-testid="routes-modal"]').exists()).toBe(true);
    expect(wrapper.get('[data-testid="routes-empty"]').text()).toBe("暂无路由。");
    expect(wrapper.findAll(".route-item")).toHaveLength(0);
  });

  it("路由列表不分页，所有条目由列表容器承载", () => {
    const routes = Array.from({ length: 7 }, (_, i) => `10.0.0.${i}/32`);
    const wrapper = mountModal(routes);

    expect(wrapper.find('[data-testid="routes-pagination"]').exists()).toBe(false);
    expect(wrapper.findAll(".route-item")).toHaveLength(7);
    expect(wrapper.get('[data-testid="route-item-6"]').text()).toContain("10.0.0.6/32");
  });

  it("以紧凑纵向顺序放置添加、合并和保存操作", () => {
    const wrapper = mountModal([]);
    const card = wrapper.get(".routes-modal-card");
    const controls = card.get(".routes-controls-stack");
    const panels = controls.findAll("section");
    const cardChildren = Array.from(card.element.children);

    expect(panels).toHaveLength(2);
    expect(panels[0].classes()).toContain("routes-add-panel");
    expect(panels[1].classes()).toContain("routes-merge-panel");
    expect(cardChildren.indexOf(controls.element)).toBeLessThan(
      cardChildren.indexOf(card.get(":scope > .modal-actions").element),
    );

    const source = readFileSync("src/components/RoutesModal.vue", "utf8");
    expect(source).toMatch(/\.routes-modal-card\s*\{[\s\S]*?width:\s*min\(100%,\s*760px\);/);
    expect(source).toMatch(/\.routes-controls-stack\s*\{[\s\S]*?display:\s*grid;[\s\S]*?gap:\s*var\(--space-2\);/);
    expect(source).toMatch(/\.routes-merge-panel\s*\{[\s\S]*?padding-block:\s*var\(--space-2\);/);
    expect(source).toMatch(/\.routes-modal-card\s*>\s*\.modal-actions\s*\{[\s\S]*?margin-top:\s*var\(--space-3\);/);
  });

  it("通过输入框添加合法 CIDR（裸 IP 或带前缀）", async () => {
    const wrapper = mountModal(["10.0.0.0/8"]);
    await wrapper.get('[data-testid="routes-add-input"]').setValue("192.168.0.0/16");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await wrapper.get('[data-testid="routes-add-input"]').setValue("10.0.0.1");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();

    const texts = wrapper.findAll(".route-item__text").map((item) => item.text());
    expect(texts).toEqual(["10.0.0.0/8", "192.168.0.0/16", "10.0.0.1"]);
    expect(wrapper.get('[data-testid="routes-add-input"]').element as HTMLInputElement).toHaveProperty("value", "");
  });

  it("添加框明确支持多行且每行一条，并把添加按钮嵌入输入框右下角", () => {
    const wrapper = mountModal([]);
    const composer = wrapper.get('[data-testid="routes-add-composer"]');

    expect(composer.get('[data-testid="routes-add-input"]').attributes("placeholder")).toBe("支持多行，每行一条");
    expect(composer.find('[data-testid="routes-add"]').exists()).toBe(true);

    const source = readFileSync("src/components/RoutesModal.vue", "utf8");
    expect(source).toMatch(/\.routes-add-composer\s*\{[\s\S]*?position:\s*relative;/);
    expect(source).toMatch(/\.routes-add-composer > button\s*\{[\s\S]*?position:\s*absolute;[\s\S]*?right:[\s\S]*?bottom:/);
  });

  it("非法输入与重复条目显示内联错误且不加入", async () => {
    const wrapper = mountModal(["10.0.0.0/8"]);
    await wrapper.get('[data-testid="routes-add-input"]').setValue("not-an-ip");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();
    expect(wrapper.get('[data-testid="routes-add-error-modal"]').text()).toContain("不是合法的 IP 或 CIDR");
    expect(wrapper.findAll(".route-item")).toHaveLength(1);

    await wrapper.get('[data-testid="routes-add-input"]').setValue("10.0.0.0/8");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();
    expect(wrapper.get('[data-testid="routes-add-error-modal"]').text()).toContain("已存在");
    expect(wrapper.findAll(".route-item")).toHaveLength(1);
  });

  it("支持粘贴多行路由，逐条加入合法项并在内模态窗汇总失败项", async () => {
    const wrapper = mountModal([]);
    await wrapper.get('[data-testid="routes-add-input"]').setValue(
      "192.168.1.0/24,\n10.0.0.1;\nnot-a-route\n10.0.0.2/33",
    );
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();

    expect(wrapper.findAll(".route-item__text").map((item) => item.text())).toEqual([
      "192.168.1.0/24",
      "10.0.0.1",
    ]);
    const error = wrapper.get('[data-testid="routes-add-error-modal"]');
    expect(error.find(".routes-nested-modal").exists()).toBe(true);
    expect(error.text()).toContain("not-a-route");
    expect(error.text()).toContain("10.0.0.2/33");
  });

  it("可删除条目；合并按钮在未选满两条时禁用", async () => {
    const wrapper = mountModal(["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    expect(wrapper.get('[data-testid="routes-merge"]').attributes("disabled")).toBeDefined();

    await wrapper.get('[data-testid="route-remove-2"]').trigger("click");
    await flushPromises();
    const texts = wrapper.findAll(".route-item__text").map((item) => item.text());
    expect(texts).toEqual(["10.0.0.1", "10.0.0.2"]);
  });

  it("合并掩码 >24（如 /31）直接应用，不弹二次确认", async () => {
    const wrapper = mountModal(["192.168.1.2", "192.168.1.3"]);
    await selectPair(wrapper, 0, 1);
    expect(wrapper.get('[data-testid="routes-merge-preview"]').text()).toContain("192.168.1.2/31");
    expect(wrapper.get('[data-testid="routes-merge"]').attributes("disabled")).toBeUndefined();

    await wrapper.get('[data-testid="routes-merge"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="routes-confirm"]').exists()).toBe(false);
    expect(wrapper.findAll(".route-item__text").map((item) => item.text())).toEqual(["192.168.1.2/31"]);
  });

  it("合并掩码不短于 16 位时直接应用，短于 16 位才确认", async () => {
    const direct = mountModal(["10.0.0.0", "10.0.1.0"]);
    await selectPair(direct, 0, 1);
    expect(direct.get('[data-testid="routes-merge-preview"]').text()).toContain("10.0.0.0/23");
    await direct.get('[data-testid="routes-merge"]').trigger("click");
    await flushPromises();
    expect(direct.find('[data-testid="routes-confirm"]').exists()).toBe(false);
    expect(direct.findAll(".route-item__text").map((item) => item.text())).toEqual(["10.0.0.0/23"]);

    const wrapper = mountModal(["10.0.0.0", "10.128.0.0"]);
    await selectPair(wrapper, 0, 1);
    expect(wrapper.get('[data-testid="routes-merge-preview"]').text()).toContain("10.0.0.0/8");

    await wrapper.get('[data-testid="routes-merge"]').trigger("click");
    await flushPromises();
    const confirm = wrapper.get('[data-testid="routes-confirm"]');
    expect(confirm.find(".routes-nested-modal").exists()).toBe(true);
    expect(confirm.text()).toContain("合并网段过大，可能导致不必要流量流经 VPN 服务器影响体验，是否继续？");
    expect(confirm.get('[data-testid="routes-confirm-result"]').text()).toContain("10.0.0.0/8");

    // 取消：不合并
    await confirm.get('[data-testid="routes-confirm-cancel"]').trigger("click");
    await flushPromises();
    expect(wrapper.find('[data-testid="routes-confirm"]').exists()).toBe(false);
    expect(wrapper.findAll(".route-item__text").map((item) => item.text())).toEqual(["10.0.0.0", "10.128.0.0"]);

    // 再次合并并确认：替换两条为合并结果
    await wrapper.get('[data-testid="routes-merge"]').trigger("click");
    await flushPromises();
    await wrapper.get('[data-testid="routes-confirm-ok"]').trigger("click");
    await flushPromises();
    expect(wrapper.findAll(".route-item__text").map((item) => item.text())).toEqual(["10.0.0.0/8"]);
  });

  it("可一次选择并合并三条以上路由，预览固定在合并控制容器内", async () => {
    const wrapper = mountModal(["10.0.0.1", "10.0.0.2", "10.0.0.4"]);
    expect(wrapper.get('[data-testid="routes-merge-preview"]').text()).toContain("未选择");
    expect(wrapper.get('[data-testid="routes-merge"]').attributes("title")).toContain("多条");

    for (const index of [0, 1, 2]) {
      await wrapper.get(`[data-testid="route-select-${index}"]`).setValue(true);
    }
    await flushPromises();

    expect(wrapper.get('[data-testid="routes-merge-preview"]').text()).toContain("10.0.0.0/29");
    expect(wrapper.get('[data-testid="routes-merge"]').attributes("disabled")).toBeUndefined();
    await wrapper.get('[data-testid="routes-merge"]').trigger("click");
    await flushPromises();
    expect(wrapper.findAll(".route-item__text").map((item) => item.text())).toEqual(["10.0.0.0/29"]);
  });

  it("保存发出最终列表；取消发出 close", async () => {
    const wrapper = mountModal(["10.0.0.0/8"]);
    await wrapper.get('[data-testid="routes-add-input"]').setValue("10.1.0.0/16");
    await wrapper.get('[data-testid="routes-add"]').trigger("click");
    await flushPromises();

    await wrapper.get('[data-testid="routes-save"]').trigger("click");
    await flushPromises();
    expect(wrapper.emitted("save")).toEqual([[["10.0.0.0/8", "10.1.0.0/16"]]]);

    await wrapper.get('[data-testid="routes-cancel"]').trigger("click");
    expect(wrapper.emitted("close")).toHaveLength(1);
  });
});
