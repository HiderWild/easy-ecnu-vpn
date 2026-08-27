// CIDR / IPv4 纯工具（前端路由设置模态使用）。
//
// 语义对齐 core 的 `parse_route_destination`（exv-vpn-win32-engine
// platform_tunnel.rs）：裸 IP → /32 主机路由；"ip/prefix" 校验 prefix 为 0-32 的
// 整数；非法 IPv4 或超界 prefix → null。`parseCidr` 不强制主机位归零（返回解析出的
// IP 规范形式）；`mergeTwoIps` 内部按 `masked_network` 逻辑（`u32::MAX << (32-prefix)`
// 屏蔽主机位）归零后给出张成两个 IP 的最小 CIDR。

export interface CidrEntry {
  /** 解析出的 IPv4 地址（主机位保留；合并逻辑内部再屏蔽）。 */
  network: string;
  prefix: number;
}

export interface MergedCidr {
  /** 合并结果的 CIDR 文本，如 "192.168.1.0/30"。 */
  cidr: string;
  prefix: number;
}

function maskForPrefix(prefix: number): number {
  return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

/** 单字节：仅接受 0 或非前导零的十进制整数（对齐 Rust Ipv4Addr 拒绝前导零）。 */
const OCTET_RE = /^(?:0|[1-9]\d*)$/;

function parseOctet(text: string): number | null {
  if (!OCTET_RE.test(text)) return null;
  const value = Number(text);
  return value <= 255 ? value : null;
}

/** 把 IPv4 点分字符串解析为无符号 32 位整数；非法返回 null。 */
export function ipToNumber(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(parseOctet);
  if (octets.some((octet) => octet === null)) return null;
  const [a, b, c, d] = octets as number[];
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

/** 把无符号 32 位整数格式化为 IPv4 点分字符串。 */
export function numberToIp(n: number): string {
  const value = n >>> 0;
  return [
    value >>> 24,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join(".");
}

/**
 * 解析一条路由目标字符串：
 *   * 裸 IP → /32 主机路由；
 *   * "ip/prefix" → 校验 prefix 为 0-32 的整数（0 合法，对齐 Rust 测试用例）；
 *   * 非法 IPv4、非整数或超界 prefix → null。
 * 不强制主机位归零。
 */
export function parseCidr(input: string): CidrEntry | null {
  const text = input.trim();
  if (text === "") return null;
  const slash = text.indexOf("/");
  let ipPart = text;
  let prefix = 32;
  if (slash !== -1) {
    if (slash !== text.lastIndexOf("/")) return null;
    ipPart = text.slice(0, slash).trim();
    const rawPrefix = text.slice(slash + 1).trim();
    if (!/^\d+$/.test(rawPrefix)) return null;
    prefix = Number(rawPrefix);
    if (prefix > 32) return null;
  }
  const numeric = ipToNumber(ipPart);
  if (numeric === null) return null;
  return { network: numberToIp(numeric), prefix };
}

/**
 * 计算两个 IPv4 张成地址空间的最小 CIDR：
 *   公共前缀长度 = clz32(ipA ^ ipB)；网络 = 基地址 & (u32::MAX << (32 - prefix))。
 *   相同 IP → /32；任一非法 → null。
 * 掩码逻辑对齐 Rust `masked_network`（prefix=0 特判，避免 JS 32 位移位回绕）。
 */
export function mergeTwoIps(ipA: string, ipB: string): MergedCidr | null {
  const a = ipToNumber(ipA);
  const b = ipToNumber(ipB);
  if (a === null || b === null) return null;
  return mergeManyCidr([
    { network: numberToIp(a), prefix: 32 },
    { network: numberToIp(b), prefix: 32 },
  ]);
}

/**
 * 计算多条 CIDR 张成地址空间的最小公共 CIDR。
 *
 * 输入项先按各自掩码展开为 [network, broadcast]，再以所有区间的最小起点和最大终点
 * 求公共前缀。这样合并已有网段时不会只看网段起始 IP，能够正确覆盖整个被选范围。
 */
export function mergeManyCidr(entries: ReadonlyArray<CidrEntry>): MergedCidr | null {
  if (entries.length === 0) return null;

  let lowest = Number.POSITIVE_INFINITY;
  let highest = 0;
  for (const entry of entries) {
    const address = ipToNumber(entry.network);
    if (address === null || !Number.isInteger(entry.prefix) || entry.prefix < 0 || entry.prefix > 32) {
      return null;
    }
    const mask = maskForPrefix(entry.prefix);
    const network = (address & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    lowest = Math.min(lowest, network);
    highest = Math.max(highest, broadcast);
  }

  const prefix = Math.clz32((lowest ^ highest) >>> 0);
  const network = (lowest & maskForPrefix(prefix)) >>> 0;
  return { cidr: `${numberToIp(network)}/${prefix}`, prefix };
}
