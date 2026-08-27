import { describe, expect, it } from "vitest";

import { commandErrorMessage } from "../command-error";

describe("commandErrorMessage", () => {
  it("优先取 Error.message", () => {
    expect(commandErrorMessage(new Error("模拟失败"), "兜底")).toBe("模拟失败");
  });

  it("识别 {kind,message} 普通对象（Tauri AppError 序列化形状）", () => {
    const error = { kind: "failed_precondition", message: "服务已安装但未运行" };
    expect(commandErrorMessage(error, "兜底")).toBe("服务已安装但未运行");
  });

  it("message 为空白字符串时回退兜底", () => {
    expect(commandErrorMessage({ kind: "internal", message: "   " }, "兜底")).toBe("兜底");
  });

  it("非对象 / 无 message 字段 / message 非字符串时回退兜底", () => {
    expect(commandErrorMessage("boom", "兜底")).toBe("兜底");
    expect(commandErrorMessage(null, "兜底")).toBe("兜底");
    expect(commandErrorMessage(undefined, "兜底")).toBe("兜底");
    expect(commandErrorMessage({ kind: "internal" }, "兜底")).toBe("兜底");
    expect(commandErrorMessage({ message: 42 }, "兜底")).toBe("兜底");
  });
});
