import { describe, expect, it } from "vitest";

import {
  ipToNumber,
  mergeManyCidr,
  mergeTwoIps,
  numberToIp,
  parseCidr,
} from "../cidr";

describe("parseCidr 路由目标解析（对齐 Rust parse_route_destination）", () => {
  it("裸 IP 视为 /32 主机路由", () => {
    expect(parseCidr("10.0.0.1")).toEqual({ network: "10.0.0.1", prefix: 32 });
    expect(parseCidr("219.228.60.69")).toEqual({ network: "219.228.60.69", prefix: 32 });
  });

  it("解析 ip/prefix，并去除首尾空白", () => {
    expect(parseCidr("10.0.0.0/8")).toEqual({ network: "10.0.0.0", prefix: 8 });
    expect(parseCidr(" 192.168.0.0/16 ")).toEqual({ network: "192.168.0.0", prefix: 16 });
    expect(parseCidr("59.78.199.0/21")).toEqual({ network: "59.78.199.0", prefix: 21 });
  });

  it("边界 prefix：0 与 32 均合法", () => {
    expect(parseCidr("10.0.0.1/0")).toEqual({ network: "10.0.0.1", prefix: 0 });
    expect(parseCidr("10.0.0.1/32")).toEqual({ network: "10.0.0.1", prefix: 32 });
  });

  it("不强制主机位归零（network 保留解析出的 IP 原样）", () => {
    expect(parseCidr("10.1.2.3/8")).toEqual({ network: "10.1.2.3", prefix: 8 });
    expect(parseCidr("192.168.1.200/24")).toEqual({ network: "192.168.1.200", prefix: 24 });
  });

  it.each([
    ["not-an-ip"],
    [""],
    ["  "],
    ["10.0.0.1/33"],
    ["10.0.0.1/"],
    ["10.0.0.1/8/9"],
    ["10.0.0.1/abc"],
    ["10.0.0.1/-1"],
    ["256.0.0.1"],
    ["01.2.3.4"], // 前导零被拒（对齐 Rust Ipv4Addr）
    ["10.0.0.1.2"],
    ["1.2.3"],
  ])("非法输入返回 null：%s", (input) => {
    expect(parseCidr(input)).toBeNull();
  });
});

describe("ipToNumber / numberToIp", () => {
  it("IPv4 点分 ↔ 无符号 32 位整数往返", () => {
    expect(ipToNumber("0.0.0.0")).toBe(0);
    expect(ipToNumber("255.255.255.255")).toBe(4_294_967_295);
    expect(ipToNumber("192.168.1.1")).toBe(0xc0a80101);
    expect(numberToIp(0)).toBe("0.0.0.0");
    expect(numberToIp(4_294_967_295)).toBe("255.255.255.255");
    expect(numberToIp(0xc0a80101)).toBe("192.168.1.1");
    expect(numberToIp(ipToNumber("10.0.0.1") as number)).toBe("10.0.0.1");
  });

  it.each([[""], ["1.2.3"], ["1.2.3.4.5"], ["256.1.1.1"], ["-1.0.0.1"], ["a.b.c.d"]])(
    "非法 IP 返回 null：%s",
    (ip) => {
      expect(ipToNumber(ip)).toBeNull();
    },
  );
});

describe("mergeTwoIps 张成地址空间的最小 CIDR", () => {
  it("相同 IP → /32", () => {
    expect(mergeTwoIps("10.0.0.5", "10.0.0.5")).toEqual({ cidr: "10.0.0.5/32", prefix: 32 });
  });

  it("相邻 .1/.2 → 公共前缀 30（覆盖 .0-.3）", () => {
    expect(mergeTwoIps("192.168.1.1", "192.168.1.2")).toEqual({
      cidr: "192.168.1.0/30",
      prefix: 30,
    });
  });

  it("相邻 .2/.3 → /31（成对主机）", () => {
    expect(mergeTwoIps("192.168.1.2", "192.168.1.3")).toEqual({
      cidr: "192.168.1.2/31",
      prefix: 31,
    });
  });

  it("跨 /24 边界（.1.255 与 .2.0）→ /22", () => {
    expect(mergeTwoIps("192.168.1.255", "192.168.2.0")).toEqual({
      cidr: "192.168.0.0/22",
      prefix: 22,
    });
  });

  it("/25 边界两侧 → /24", () => {
    expect(mergeTwoIps("192.168.1.127", "192.168.1.128")).toEqual({
      cidr: "192.168.1.0/24",
      prefix: 24,
    });
  });

  it("全区间端点 → /0", () => {
    expect(mergeTwoIps("0.0.0.0", "255.255.255.255")).toEqual({ cidr: "0.0.0.0/0", prefix: 0 });
  });

  it("任一 IP 非法 → null", () => {
    expect(mergeTwoIps("10.0.0.1", "not-an-ip")).toBeNull();
    expect(mergeTwoIps("", "10.0.0.2")).toBeNull();
  });

  it("多条地址取覆盖全部输入的最小公共 CIDR", () => {
    expect(
      mergeManyCidr([
        { network: "10.0.0.1", prefix: 32 },
        { network: "10.0.0.2", prefix: 32 },
        { network: "10.0.0.4", prefix: 32 },
      ]),
    ).toEqual({ cidr: "10.0.0.0/29", prefix: 29 });
  });
});
