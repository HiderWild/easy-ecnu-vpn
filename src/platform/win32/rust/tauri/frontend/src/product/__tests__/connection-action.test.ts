import { describe, expect, it } from "vitest";

import { connectionActionFor } from "../connection-action";
import { present } from "../presenter";
import {
  snapshotConnected,
  snapshotFailedClean,
  snapshotFailedDirty,
  snapshotIdle,
  snapshotConnecting,
  snapshotStopping,
} from "../../test/fixtures";

describe("产品连接动作", () => {
  it("失败且有错误时提供重试", () => {
    expect(connectionActionFor(present(snapshotFailedClean(), 0))).toEqual({
      kind: "connect",
      label: "重试",
      enabled: true,
    });
  });

  it("可连接时提供连接", () => {
    expect(connectionActionFor(present(snapshotIdle(), 0))).toEqual({
      kind: "connect",
      label: "连接",
      enabled: true,
    });
  });

  it("连接中停止动作显示取消", () => {
    expect(connectionActionFor(present(snapshotConnecting("connecting_control"), 0))).toEqual({
      kind: "stop",
      label: "取消",
      enabled: true,
    });
  });

  it("已连接停止动作显示断开", () => {
    expect(connectionActionFor(present(snapshotConnected(), 0))).toEqual({
      kind: "stop",
      label: "断开",
      enabled: true,
    });
  });

  it("脏失败同样可重试（不禁用按钮，避免无恢复路径死锁）；停止中显示处理中", () => {
    expect(connectionActionFor(present(snapshotFailedDirty(), 0))).toEqual({
      kind: "connect",
      label: "重试",
      enabled: true,
    });
    expect(connectionActionFor(present(snapshotStopping(), 0))).toEqual({
      kind: "none",
      label: "处理中",
      enabled: false,
    });
  });
});
