import type { InjectionKey } from "vue";

import { kernel } from "../lib/ipc";

export const CORE_CONFIG_KEYS = [
  "server",
  "username",
  "password",
  "remember_password",
  "routes",
  "user_agent",
  "mtu",
  "auto_reconnect",
  "auto_reconnect_max_attempts",
] as const;

export type CoreConfigKey = (typeof CORE_CONFIG_KEYS)[number];

export interface CoreConfigItem {
  key: string;
  value: string;
}

export interface CoreConfigGateway {
  configGet(): Promise<ReadonlyArray<CoreConfigItem>>;
  configSet(items: ReadonlyArray<{ key: CoreConfigKey; value: string }>): Promise<boolean>;
}

/** 应用入口在预览模式下可注入内存网关；生产页面仍默认连接真实 core。 */
export const CORE_CONFIG_GATEWAY_KEY: InjectionKey<CoreConfigGateway> = Symbol(
  "exv.product.core-config-gateway",
);

export interface CoreConfigField {
  key: CoreConfigKey;
  label: string;
  description: string;
  kind: "text" | "password" | "boolean" | "routes" | "mtu" | "number" | "server";
}

export const CORE_CONFIG_FIELDS: readonly CoreConfigField[] = [
  { key: "server", label: "VPN 服务器", description: "用于建立 VPN 连接的服务地址。", kind: "server" },
  { key: "username", label: "登录账户", description: "连接时使用的账户名。", kind: "text" },
  { key: "password", label: "密码", description: "留空表示保持已保存密码。", kind: "password" },
  { key: "remember_password", label: "记住密码", description: "勾选后密码随配置保存；关闭则连接时需手动输入。", kind: "boolean" },
  { key: "routes", label: "路由", description: "由EXV处理的流量的目标地址范围", kind: "routes" },
  { key: "user_agent", label: "User-Agent", description: "连接请求使用的客户端标识。", kind: "text" },
  { key: "mtu", label: "MTU", description: "网络接口的正整数 MTU。", kind: "mtu" },
  { key: "auto_reconnect", label: "自动重连", description: "连接意外断开时自动重新连接（下次连接生效）。", kind: "boolean" },
  { key: "auto_reconnect_max_attempts", label: "自动重连次数", description: "仅在开启自动重连后可设置；0 表示无限重连；达到次数后不再重连。", kind: "number" },
];

/** VPN 服务器预设地址（与旧 C++ distribution/ecnu.json 对齐；默认 vpn-cn）。 */
export const VPN_SERVERS: readonly { label: string; value: string }[] = [
  { label: "ECNU CN", value: "vpn-cn.ecnu.edu.cn" },
  { label: "ECNU CT", value: "vpn-ct.ecnu.edu.cn" },
  { label: "ECNU LT", value: "vpn-lt.ecnu.edu.cn" },
];

/** 归一化 VPN 服务器地址：去除协议前缀、尾部斜杠并统一小写。 */
export function normalizeServerValue(raw: string): string {
  return raw.trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "").toLowerCase();
}

export function isVpnServerPreset(value: string): boolean {
  return VPN_SERVERS.some((server) => server.value === value);
}

export type NormalizedCoreConfigValue =
  | { ok: true; value: string }
  | { ok: false; message: string };

export function isCoreConfigKey(key: string): key is CoreConfigKey {
  return (CORE_CONFIG_KEYS as readonly string[]).includes(key);
}

export function normalizeCoreConfigValue(key: CoreConfigKey, raw: string): NormalizedCoreConfigValue {
  if (key === "routes") {
    return {
      ok: true,
      value: raw
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
        .join(","),
    };
  }

  if (key === "mtu") {
    const value = raw.trim();
    return /^[1-9]\d*$/.test(value)
      ? { ok: true, value }
      : { ok: false, message: "MTU 必须是正整数。" };
  }

  if (key === "auto_reconnect") {
    return raw === "true" || raw === "false"
      ? { ok: true, value: raw }
      : { ok: false, message: "自动重连只能是 true 或 false。" };
  }

  if (key === "auto_reconnect_max_attempts") {
    const value = raw.trim();
    return /^(0|[1-9]\d*)$/.test(value) && Number(value) <= 1024
      ? { ok: true, value }
      : { ok: false, message: "自动重连次数必须是 0-1024 的整数。" };
  }

  if (key === "remember_password") {
    return raw === "true" || raw === "false"
      ? { ok: true, value: raw }
      : { ok: false, message: "记住密码只能是 true 或 false。" };
  }

  if (key === "server") {
    return { ok: true, value: normalizeServerValue(raw) };
  }

  return { ok: true, value: raw };
}

/** 生产页面唯一可用的 core 配置出口。 */
export function createCoreConfigGateway(): CoreConfigGateway {
  return {
    async configGet() {
      const payload = await kernel.configGet();
      return payload.items;
    },
    configSet(items) {
      return kernel.configSet([...items]);
    },
  };
}
