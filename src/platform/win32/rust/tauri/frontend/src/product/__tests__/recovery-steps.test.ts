import { describe, expect, it } from "vitest";

import {
  initialSteps,
  markCurrent,
  markDone,
  markFailed,
  RECOVERY_STEP_DEFS,
  stepMarker,
} from "../recovery-steps";

describe("服务恢复步骤序列", () => {
  it("clean = 卸载 + 连接；reinstall = 安装 + 连接（不拆 stop，install 内部处理运行中服务）", () => {
    expect(RECOVERY_STEP_DEFS.clean.map((s) => s.id)).toEqual(["uninstall", "connect"]);
    expect(RECOVERY_STEP_DEFS.reinstall.map((s) => s.id)).toEqual(["install", "connect"]);
  });

  it("初始全部 pending；markCurrent 置当前、markDone 完成、markFailed 失败", () => {
    let steps = initialSteps("reinstall");
    expect(steps.every((s) => s.status === "pending")).toBe(true);

    steps = markCurrent(steps, "install");
    expect(steps.find((s) => s.id === "install")?.status).toBe("current");

    steps = markDone(steps, "install");
    steps = markCurrent(steps, "connect");
    expect(steps.find((s) => s.id === "install")?.status).toBe("done");
    expect(steps.find((s) => s.id === "connect")?.status).toBe("current");

    steps = markFailed(steps, "connect");
    expect(steps.find((s) => s.id === "connect")?.status).toBe("failed");
  });

  it("步骤标记符号稳定", () => {
    expect(stepMarker("pending")).toBe("○");
    expect(stepMarker("current")).toBe("●");
    expect(stepMarker("done")).toBe("✓");
    expect(stepMarker("failed")).toBe("✗");
  });
});
