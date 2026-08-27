import { readFileSync } from "node:fs";

import { flushPromises, mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import LogsPage from "../../pages/LogsPage.vue";
import { LOGS_GATEWAY_KEY, type LogsGateway } from "../../product/logs";
import { resetLogsState } from "../../product/logs-state";

function logsGateway(entries: ReadonlyArray<{
  level: string;
  component: string;
  code: string;
  message: string;
  fields: Record<string, string>;
  timestamp_ms: number;
}>): LogsGateway & {
  logsList: ReturnType<typeof vi.fn>;
  logsClear: ReturnType<typeof vi.fn>;
  emitLog: (entry: (typeof entries)[number]) => void;
} {
  let emit: ((entry: (typeof entries)[number]) => void) | null = null;
  return {
    logsList: vi.fn(async () => ({ events: [...entries], next_after_seq: entries.length, has_more: false })),
    logsClear: vi.fn(async () => ({ cleared: true, removed_entries: entries.length })),
    onLogs: vi.fn(async (callback) => {
      emit = callback;
      return () => undefined;
    }),
    emitLog(entry) {
      emit?.(entry);
    },
  };
}

describe("日志页", () => {
  beforeEach(() => {
    resetLogsState();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("先读取历史；事件 seam 到达时可追加，但不声称已经接通实时流", async () => {
    const gateway = logsGateway([
      {
        level: "info",
        component: "core",
        code: "ready",
        message: "已有记录",
        fields: {},
        timestamp_ms: 1,
      },
    ]);
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    expect(gateway.logsList).toHaveBeenCalledOnce();
    expect(wrapper.text()).toContain("已有记录");
    expect(wrapper.text()).not.toContain("实时同步中");

    gateway.emitLog({
      level: "info",
      component: "core",
      code: "next",
      message: "新到达的记录",
      fields: {},
      timestamp_ms: 2,
    });
    await flushPromises();
    expect(wrapper.text()).toContain("新到达的记录");
    wrapper.unmount();
  });

  it("切页重挂载后只拉增量（懒加载：首次全量，后续传日志尾取增量）", async () => {
    const gateway = logsGateway([
      {
        level: "info",
        component: "core",
        code: "ready",
        message: "已有记录",
        fields: {},
        timestamp_ms: 1,
      },
    ]);
    const first = mount(LogsPage, { props: { gateway } });
    await flushPromises();
    expect(gateway.logsList).toHaveBeenCalledTimes(1);
    first.unmount();

    const second = mount(LogsPage, { props: { gateway } });
    await flushPromises();
    // 重挂载：从上次日志尾（next_after_seq=1）增量拉取，不重新全量。
    expect(gateway.logsList).toHaveBeenCalledTimes(2);
    expect(gateway.logsList.mock.calls[1][0]).toBe(1);
    expect(second.text()).toContain("已有记录"); // 模块级条目保留 + 增量去重
    second.unmount();
  });

  it("历史读取失败时给出重试入口，而不把失败伪装成空日志", async () => {
    const gateway: LogsGateway = {
      logsList: vi.fn(async () => {
        throw new Error("unavailable");
      }),
      logsClear: vi.fn(async () => ({ cleared: true, removed_entries: 0 })),
      onLogs: vi.fn(async () => () => undefined),
    };
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    expect(wrapper.text()).toContain("暂时无法读取日志");
    expect(wrapper.find('[data-testid="retry-logs"]').exists()).toBe(true);
    expect(wrapper.text()).not.toContain("暂无历史日志");
    wrapper.unmount();
  });

  it("可从应用注入取得预览日志网关", async () => {
    const gateway = logsGateway([]);
    const wrapper = mount(LogsPage, {
      global: { provide: { [LOGS_GATEWAY_KEY as symbol]: gateway } },
    });
    await flushPromises();

    expect(gateway.logsList).toHaveBeenCalledOnce();
    expect(wrapper.text()).toContain("暂无日志");
    wrapper.unmount();
  });

  it("过滤历史与实时事件中的 keepalive 和数据面计数诊断记录", async () => {
    const gateway = logsGateway([
      {
        level: "info",
        component: "engine",
        code: "keepalive",
        message: "keepalive heartbeat received (diagnostic)",
        fields: {},
        timestamp_ms: 1,
      },
      {
        level: "info",
        component: "engine",
        code: "tunnel.dataplane.counters",
        message: "data plane ring counters (diagnostic)",
        fields: { ring_received: "1024", ring_sent: "512" },
        timestamp_ms: 2,
      },
      {
        level: "error",
        component: "core",
        code: "failure",
        message: "应当保留的错误",
        fields: {},
        timestamp_ms: 3,
      },
    ]);
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    expect(wrapper.text()).not.toContain("keepalive heartbeat received");
    expect(wrapper.text()).not.toContain("data plane ring counters");
    expect(wrapper.text()).toContain("应当保留的错误");

    gateway.emitLog({
      level: "info",
      component: "engine",
      code: "keepalive",
      message: "keepalive heartbeat received (diagnostic)",
      fields: {},
      timestamp_ms: 3,
    });
    await flushPromises();
    expect(wrapper.text()).not.toContain("keepalive heartbeat received");

    gateway.emitLog({
      level: "info",
      component: "engine",
      code: "tunnel.dataplane.counters",
      message: "data plane ring counters (diagnostic)",
      fields: { ring_received: "2048", ring_sent: "1024" },
      timestamp_ms: 4,
    });
    await flushPromises();
    expect(wrapper.text()).not.toContain("data plane ring counters");
    wrapper.unmount();
  });

  it("支持按日志等级筛选，并默认勾选跟随最新", async () => {
    const gateway = logsGateway([
      { level: "info", component: "core", code: "i", message: "信息日志", fields: {}, timestamp_ms: 1 },
      { level: "warn", component: "core", code: "w", message: "警告日志", fields: {}, timestamp_ms: 2 },
      { level: "error", component: "core", code: "e", message: "错误日志", fields: {}, timestamp_ms: 3 },
    ]);
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    const follow = wrapper.get('[data-testid="logs-follow-latest"]');
    expect((follow.element as HTMLInputElement).checked).toBe(true);
    expect(wrapper.get('[data-testid="log-level-filter"]').element).toHaveProperty("value", "all");

    await wrapper.get('[data-testid="log-level-filter"]').setValue("error");
    expect(wrapper.text()).toContain("错误日志");
    expect(wrapper.text()).not.toContain("信息日志");
    expect(wrapper.text()).not.toContain("警告日志");

    await follow.setValue(false);
    expect((follow.element as HTMLInputElement).checked).toBe(false);
    wrapper.unmount();
  });

  it("通过增量轮询实时接收新日志，而不提供刷新历史按钮", async () => {
    vi.useFakeTimers();
    const initial = {
      level: "info",
      component: "core",
      code: "initial",
      message: "初始日志",
      fields: {},
      timestamp_ms: 1,
    } as const;
    const next = {
      level: "info",
      component: "core",
      code: "next",
      message: "轮询到的新日志",
      fields: {},
      timestamp_ms: 2,
    } as const;
    const gateway = logsGateway([initial]);
    gateway.logsList.mockResolvedValueOnce({
      events: [initial],
      next_after_seq: 1,
      has_more: false,
    });
    gateway.logsList.mockResolvedValue({
      events: [next],
      next_after_seq: 2,
      has_more: false,
    });
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    expect(wrapper.text()).toContain("初始日志");
    expect(wrapper.text()).not.toContain("轮询到的新日志");
    expect(wrapper.find('[data-testid="refresh-history"]').exists()).toBe(false);

    await vi.advanceTimersByTimeAsync(1_000);
    expect(wrapper.text()).toContain("轮询到的新日志");
    wrapper.unmount();
  });

  it("日志外壳和表头在增量轮询中保持挂载，完整批次就绪后才追加", async () => {
    vi.useFakeTimers();
    const initial = {
      level: "info",
      component: "core",
      code: "initial",
      message: "初始日志",
      fields: {},
      timestamp_ms: 1,
    } as const;
    const incoming = {
      level: "info",
      component: "core",
      code: "incoming",
      message: "完整批次的新日志",
      fields: {},
      timestamp_ms: 2,
    } as const;
    type LogsListReply = Awaited<ReturnType<LogsGateway["logsList"]>>;
    let callCount = 0;
    let releaseIncrement: ((reply: LogsListReply) => void) | undefined;
    const gateway: LogsGateway = {
      logsList: vi.fn(() => {
        callCount += 1;
        if (callCount === 1) {
          return Promise.resolve({ events: [initial], next_after_seq: 1, has_more: false });
        }
        return new Promise<LogsListReply>((resolve) => {
          releaseIncrement = resolve;
        });
      }),
      logsClear: vi.fn(async () => ({ cleared: true, removed_entries: 0 })),
      onLogs: vi.fn(async () => () => undefined),
    };
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    const table = wrapper.get('[data-testid="log-table"]');
    const body = wrapper.get('[data-testid="logs-scroll-body"]');
    expect(table.find('[data-testid="logs-table-header"]').exists()).toBe(true);
    expect(body.element.parentElement).toBe(table.element);

    await vi.advanceTimersByTimeAsync(1_000);
    await Promise.resolve();
    expect(wrapper.get('[data-testid="logs-scroll-body"]').element).toBe(body.element);
    expect(wrapper.text()).toContain("初始日志");
    expect(wrapper.text()).not.toContain("正在读取历史记录…");
    expect(releaseIncrement).toBeDefined();

    releaseIncrement?.({ events: [incoming], next_after_seq: 2, has_more: false });
    await flushPromises();
    expect(wrapper.text()).toContain("完整批次的新日志");

    const source = readFileSync("src/pages/LogsPage.vue", "utf8");
    expect(source).toContain('v-else-if="isInitialLoading"');
    expect(source).not.toContain('v-else-if="loading"');
    wrapper.unmount();
  });

  it("清空日志调用持久化清理 RPC，并清除全部历史条目", async () => {
    const gateway = logsGateway([
      { level: "info", component: "core", code: "old", message: "历史日志", fields: {}, timestamp_ms: 1 },
    ]);
    const wrapper = mount(LogsPage, { props: { gateway } });
    await flushPromises();

    const clear = wrapper.get('[data-testid="clear-logs"]');
    expect(clear.text()).toBe("清空日志");
    expect(wrapper.text()).not.toContain("清空当前视图");
    expect(wrapper.text()).not.toContain("刷新历史");

    await clear.trigger("click");
    await flushPromises();
    expect(gateway.logsClear).toHaveBeenCalledOnce();
    expect(wrapper.text()).not.toContain("历史日志");
    expect(wrapper.text()).toContain("暂无日志");
    wrapper.unmount();
  });
});
