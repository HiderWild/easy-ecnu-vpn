import { describe, expect, it } from "vitest";

import {
  CORE_CONFIG_FIELDS,
  CORE_CONFIG_KEYS,
  normalizeCoreConfigValue,
} from "../core-config";

describe("核心配置产品边界", () => {
  it("只公开九个可编辑的核心键（含密码——设置页密码框专用）", () => {
    expect(CORE_CONFIG_KEYS).toEqual([
      "server",
      "username",
      "password",
      "remember_password",
      "routes",
      "user_agent",
      "mtu",
      "auto_reconnect",
      "auto_reconnect_max_attempts",
    ]);
  });

  it("设置说明只保留有效信息，不再展示服务器、密码和路由的幽灵文案", () => {
    const descriptions = new Map(CORE_CONFIG_FIELDS.map((field) => [field.key, field.description]));

    expect(descriptions.get("server")).toBe("用于建立 VPN 连接的服务地址。");
    expect(descriptions.get("password")).toBe("留空表示保持已保存密码。");
    expect(descriptions.get("routes")).toBe("由EXV处理的流量的目标地址范围");
  });

  it("在提交前规范化路由并拒绝无效 MTU", () => {
    expect(normalizeCoreConfigValue("routes", " 10.0.0.0/8, , 192.168.0.0/16 ")).toEqual({
      ok: true,
      value: "10.0.0.0/8,192.168.0.0/16",
    });
    expect(normalizeCoreConfigValue("mtu", "1420")).toEqual({ ok: true, value: "1420" });
    expect(normalizeCoreConfigValue("mtu", "1420.5")).toEqual({
      ok: false,
      message: "MTU 必须是正整数。",
    });
  });

  it("只接受字符串 true 或 false 作为记住密码的配置值", () => {
    expect(normalizeCoreConfigValue("remember_password", "true")).toEqual({ ok: true, value: "true" });
    expect(normalizeCoreConfigValue("remember_password", "yes")).toEqual({
      ok: false,
      message: "记住密码只能是 true 或 false。",
    });
  });

  it("自动重连开关只接受字符串 true 或 false", () => {
    expect(normalizeCoreConfigValue("auto_reconnect", "true")).toEqual({ ok: true, value: "true" });
    expect(normalizeCoreConfigValue("auto_reconnect", "false")).toEqual({ ok: true, value: "false" });
    expect(normalizeCoreConfigValue("auto_reconnect", "1")).toEqual({
      ok: false,
      message: "自动重连只能是 true 或 false。",
    });
    expect(normalizeCoreConfigValue("auto_reconnect", "yes")).toEqual({
      ok: false,
      message: "自动重连只能是 true 或 false。",
    });
  });

  it("VPN 服务器保存前归一化：去协议、去尾部斜杠并小写；预设列表含三地 ECNU", () => {
    expect(normalizeCoreConfigValue("server", "vpn-cn.ecnu.edu.cn")).toEqual({
      ok: true,
      value: "vpn-cn.ecnu.edu.cn",
    });
    expect(normalizeCoreConfigValue("server", "HTTPS://VPN-LT.ECNU.EDU.CN/")).toEqual({
      ok: true,
      value: "vpn-lt.ecnu.edu.cn",
    });
    expect(normalizeCoreConfigValue("server", " http://vpn-ct.ecnu.edu.cn/// ")).toEqual({
      ok: true,
      value: "vpn-ct.ecnu.edu.cn",
    });
  });

  it("自动重连次数接受 0-1024 的整数，拒绝负数/小数/超限/非法字符", () => {
    expect(normalizeCoreConfigValue("auto_reconnect_max_attempts", "0")).toEqual({ ok: true, value: "0" });
    expect(normalizeCoreConfigValue("auto_reconnect_max_attempts", "5")).toEqual({ ok: true, value: "5" });
    expect(normalizeCoreConfigValue("auto_reconnect_max_attempts", "1024")).toEqual({
      ok: true,
      value: "1024",
    });
    expect(normalizeCoreConfigValue("auto_reconnect_max_attempts", " 3 ")).toEqual({
      ok: true,
      value: "3",
    });
    for (const invalid of ["-1", "1.5", "1025", "abc", ""]) {
      expect(normalizeCoreConfigValue("auto_reconnect_max_attempts", invalid)).toEqual({
        ok: false,
        message: "自动重连次数必须是 0-1024 的整数。",
      });
    }
  });
});
