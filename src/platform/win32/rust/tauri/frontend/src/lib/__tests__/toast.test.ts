import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { clearToasts, dismissToast, pushToast, useToasts } from "../toast";

describe("toast 状态存储", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    clearToasts();
  });

  afterEach(() => {
    vi.useRealTimers();
    clearToasts();
  });

  it("pushToast 加入队列，自动超时消除（默认 4s）", () => {
    pushToast("连接失败", "error");
    expect(useToasts().toasts).toHaveLength(1);
    expect(useToasts().toasts[0]).toMatchObject({ message: "连接失败", kind: "error" });

    vi.advanceTimersByTime(4001);
    expect(useToasts().toasts).toHaveLength(0);
  });

  it("dismissToast 提前消除指定 toast（点击关闭）", () => {
    pushToast("a");
    pushToast("b");
    const first = useToasts().toasts[0];
    dismissToast(first.id);
    expect(useToasts().toasts.map((t) => t.message)).toEqual(["b"]);
  });

  it("clearToasts 清空（测试重置）", () => {
    pushToast("a");
    pushToast("b");
    clearToasts();
    expect(useToasts().toasts).toHaveLength(0);
  });
});
