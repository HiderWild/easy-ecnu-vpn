import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import {
  createMockCoreConfigGateway,
  createMockLogsGateway,
} from "../mock-page-data";

describe("预览页本地模拟数据", () => {
  it("核心配置只在内存中读写，不调用真实 Tauri 接口", async () => {
    const gateway = createMockCoreConfigGateway();

    await expect(gateway.configSet([{ key: "mtu", value: "1380" }])).resolves.toBe(true);
    await expect(gateway.configGet()).resolves.toContainEqual({ key: "mtu", value: "1380" });
  });

  it("提供可读历史日志，但不会伪造自动到达的实时事件", async () => {
    const gateway = createMockLogsGateway(() => 1_725_000_000_000);
    const listener = vi.fn();

    await expect(gateway.logsList(0, 500)).resolves.toMatchObject({ has_more: false });
    const unlisten = await gateway.onLogs(listener);

    expect(listener).not.toHaveBeenCalled();
    expect(typeof unlisten).toBe("function");
    unlisten();
  });

  it("只在既有预览开关启用时由入口提供页面模拟数据", () => {
    const source = readFileSync("src/main.ts", "utf8");

    expect(source).toContain("source === \"mock\"");
    expect(source).toContain("createMockCoreConfigGateway");
    expect(source).toContain("createMockLogsGateway");
  });
});
