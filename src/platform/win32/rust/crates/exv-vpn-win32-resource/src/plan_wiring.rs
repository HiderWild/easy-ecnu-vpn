// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Domain `TunnelPlan` -> resource `ApplyPlan` wiring (Phase 7 C1).
//!
//! The helper consumes the negotiated domain plan (`control_bypass`,
//! `ipv4_routes`, `dns_servers`, `ipv4_address`/`mtu`) and turns it into the
//! committed [`ApplyPlan`] of the cross-family aggregate (`apply_tunnel`).
//! This module is pure wiring — every leaf type stays the committed type
//! (`IpAddressRow` / `RouteRow` / `DnsSettings`), and every native effect is
//! delegated to the leaf seams; nothing here re-implements a primitive.
//!
//! C++ reference (`native_ip_config.cpp:456-810`): a `server_bypass` route is a
//! `/32` on the control destination, installed with the **physical** interface
//! index + next-hop captured by `GetBestRoute2` *before* the tunnel route
//! exists, and the whole route set is installed at metric 1. This module's
//! bypass construction follows that: `bypass_route::capture` (the frozen W20
//! seam) is called while the routing table still has no tunnel route — the
//! plan is built before any apply effect runs.

use std::net::Ipv4Addr;

use exv_vpn_domain::ports::{Ipv4Route, TunnelPlan};

use crate::apply_tunnel::{build_apply_plan, ApplyPlan};
use crate::bypass_route;
use crate::dns_types::DnsSettings;
use crate::ip_helper_types::IpAddressRow;
use crate::native_error::NativeError;
use crate::routes::RouteRow;

/// `ERROR_NOT_FOUND`：`GetBestRoute2` 无路由（1168；`bypass_route::capture`
/// 的 `Ok(None)` 对应此码——控制目的地无任何路由是可安装失败的配置错误）。
const ERROR_NOT_FOUND: u32 = 1168;

/// Bypass `/32` 路由度量（C++ `to_route_row` 的冻结 `Metric = 1`；低度量钉死
/// 物理出口，压过 Mihomo 默认路由）。
const BYPASS_ROUTE_METRIC: u32 = 1;
/// Bypass 前缀长度：每个控制目的地一条 `/32`（C++ `server_bypass` 默认前缀 32）。
const BYPASS_ROUTE_PREFIX: u8 = 32;
/// 隧道路由度量（**C2 G-③ on-link**：metric 1 钉死隧道接口活跃选路；对照 C++
/// `native_ip_config.cpp:793` 语义——网关式 + metric5 是反模式，另一 TUN 占默认
/// 路由时会掉出活跃选路，on-link + 低 metric 保持活跃）。
const TUNNEL_ROUTE_METRIC: u32 = 1;

/// 把一个协商好的 domain `TunnelPlan` 组装为接口 `luid` 上的完整跨族
/// `ApplyPlan`（地址 / MTU / bypass / 隧道路由 / DNS）。
///
/// `control_bypass` 在**任何 apply effect 之前**经 `GetBestRoute2` 解析为物理
/// 出口的 `/32` 精确行（W20 冻结事实：隧道路由入表后无源查找会返回隧道接口，
/// 解析必须先于隧道路由安装；本模块在 apply 前构建计划，天然满足）。
///
/// # Errors
///
/// 任一 `control_bypass` 目的地的 `GetBestRoute2` 失败（非 1168）或无路由
/// （1168）→ 返回 [`NativeError`]（对齐 C++ `best_route_failed`：bypass 解析
/// 失败整体拒绝，不留半状态）。
pub fn apply_plan_from_tunnel(
    plan: &TunnelPlan,
    luid: u64,
) -> Result<ApplyPlan, NativeError> {
    let addresses = vec![IpAddressRow::new(plan.ipv4_address, luid, plan.ipv4_prefix_len)];
    let bypass = bypass_routes_from_control(&plan.control_bypass)?;
    let tunnel_routes = tunnel_routes_from_plan(plan, luid);
    let dns = DnsSettings::new(
        plan.dns_servers.iter().map(ToString::to_string).collect(),
        Vec::new(),
    );
    // TK1b：系统代理豁免条目随 TunnelPlan.proxy_exempt（wire 解冻字段）到达；
    // v1 借道 control_bypass 的精确 IP 已在 bypass 集合内，proxy_exempt 独立
    // 字段当前由 engine 侧填充（空 = family 零动作候选）。SID 由调用方注入
    // （engine --user-sid）；此处占位空串，family 在 apply 时防御性跳过。
    Ok(build_apply_plan(
        addresses,
        u32::from(plan.mtu),
        None,
        bypass,
        tunnel_routes,
        dns,
        // domain `TunnelPlan`（common 冻结面）暂无 proxy_exempt 字段；v1 豁免
        // 条目 = control_bypass 精确 IP 的字符串形态（与 bypass 集合同源，见
        // 设计 §5.4 借道路径）。wire 解冻字段的消费接线随 EXV_PAC_FAMILY/
        // engine 侧任务一并做。
        plan.control_bypass.iter().map(ToString::to_string).collect(),
        String::new(),
    ))
}

/// 把 `control_bypass`（控制面目的地址集合）解析为物理出口 `/32` bypass 精确行。
///
/// 每个控制目的地：`GetBestRoute2` 抓**当前**最优路由（隧道路由尚未入表 →
/// 宿主自身最优路由 = 物理出口）→ 取其物理 `interface_luid` 与 `next_hop` →
/// 以 `/32` 前缀、metric 1 构造精确行（C++ `native_ip_config.cpp:783-792`）。
///
/// # Errors
///
/// 任一目的地的 `GetBestRoute2` 失败（非 1168）或无路由（1168）→ 返回
/// [`NativeError`]（对齐 C++：bypass 解析失败整体拒绝）。
pub fn bypass_routes_from_control(
    control_bypass: &[Ipv4Addr],
) -> Result<Vec<RouteRow>, NativeError> {
    bypass_routes_from_control_with(control_bypass, bypass_route::capture)
}

/// 内部 seam（单测注入 `capture`）：把 `control_bypass` 解析为物理出口 `/32` 精确行。
///
/// `capture` 的注入使 bypass 形状（`/32` + metric 1 + 物理 next_hop）可在不触发真实
/// `GetBestRoute2` 的前提下单测；生产路径恒为 `bypass_route::capture`。
fn bypass_routes_from_control_with(
    control_bypass: &[Ipv4Addr],
    capture: impl Fn(Ipv4Addr) -> Result<Option<RouteRow>, NativeError>,
) -> Result<Vec<RouteRow>, NativeError> {
    let mut rows = Vec::with_capacity(control_bypass.len());
    for dest in control_bypass {
        let best = match capture(*dest)? {
            Some(best) => best,
            None => {
                return Err(NativeError::from_win32(
                    ERROR_NOT_FOUND,
                    "plan_wiring: control_bypass 目的地无路由（GetBestRoute2 -> 1168）",
                ));
            }
        };
        rows.push(RouteRow::new(
            *dest,
            BYPASS_ROUTE_PREFIX,
            best.next_hop,
            best.interface_luid,
            BYPASS_ROUTE_METRIC,
        ));
    }
    Ok(rows)
}

/// 把协商的 `ipv4_routes` 组装为隧道接口 `luid` 上的精确行。
///
/// **C2 G-③**：on-link 语义——`next_hop` 清空（Wintun 路由直挂隧道接口）、
/// metric 1；对照 C++ `native_ip_config.cpp:793`（网关式路由在另一 TUN 占默认
/// 路由时掉出活跃选路，on-link + 低 metric 保持活跃）。
#[must_use]
pub fn tunnel_routes_from_plan(plan: &TunnelPlan, luid: u64) -> Vec<RouteRow> {
    plan.ipv4_routes
        .iter()
        .map(|route| tunnel_route_row(route, luid))
        .collect()
}

/// 单条隧道路由的精确行构造（[`tunnel_routes_from_plan`] 的逐行 seam；C2 完成
/// G-③：on-link + metric 1）。
///
/// Wintun 路由直接挂在隧道接口上；用隧道地址作网关会让路由在另一 TUN 占默认
/// 路由时掉出 Windows 活跃选路（C++ `native_ip_config.cpp:793` 注释），on-link
/// （`next_hop` 清空）+ 低 metric 保持活跃。
#[must_use]
pub fn tunnel_route_row(route: &Ipv4Route, luid: u64) -> RouteRow {
    RouteRow::new(
        route.network,
        route.prefix_len,
        Ipv4Addr::UNSPECIFIED,
        luid,
        TUNNEL_ROUTE_METRIC,
    )
}

#[cfg(test)]
mod tests {
    use exv_vpn_domain::identity::ResourceIdentityDigest;
    use exv_vpn_domain::ports::{Ipv4Route, TunnelIntentRef, TunnelPlan};

    use super::*;
    use crate::apply_tunnel::FamilyStep;
    use crate::ip_helper_types::IpAddressRow;

    /// 组装一个 `control_bypass` 为空的合法 `TunnelPlan`（不触发真实 `GetBestRoute2`）。
    fn plan_without_bypass() -> TunnelPlan {
        let intent =
            TunnelIntentRef::try_from(ResourceIdentityDigest::try_from([0x11; 32]).unwrap())
                .unwrap();
        TunnelPlan::try_from((
            Ipv4Addr::from([10, 0, 0, 1]),
            24,
            1400,
            vec![Ipv4Route {
                network: Ipv4Addr::from([10, 0, 0, 0]),
                prefix_len: 24,
            }],
            vec![Ipv4Addr::from([1, 1, 1, 1])],
            vec![],
            intent,
        ))
        .expect("valid tunnel plan")
    }

    /// 注入 `capture` 的 seam：每个控制目的地解析为物理出口 `/32` 精确行，metric 1，
    /// next_hop/接口 LUID 取 `capture` 结果（C++ `native_ip_config.cpp:783-792` 语义）。
    #[test]
    fn bypass_rows_are_physical_32_metric_1() {
        let control = [Ipv4Addr::from([10, 1, 1, 1]), Ipv4Addr::from([10, 2, 2, 2])];
        let rows = bypass_routes_from_control_with(&control, |dest| {
            Ok(Some(RouteRow::new(
                dest,
                0,
                Ipv4Addr::from([192, 168, 1, 254]),
                0x7777,
                10,
            )))
        })
        .expect("bypass rows");
        assert_eq!(rows.len(), 2);
        // 每行：dest /32、物理 next_hop、物理接口 LUID、metric 1。
        for (i, dest) in control.iter().enumerate() {
            let row = &rows[i];
            assert_eq!(row.network, *dest);
            assert_eq!(row.prefix_len, BYPASS_ROUTE_PREFIX);
            assert_eq!(row.next_hop, Ipv4Addr::from([192, 168, 1, 254]));
            assert_eq!(row.interface_luid, 0x7777);
            assert_eq!(row.metric, BYPASS_ROUTE_METRIC);
        }
    }

    /// `control_bypass` 目的地无路由（`GetBestRoute2` → 1168）→ 整体拒绝（对齐 C++
    /// `best_route_failed`：bypass 解析失败不留半状态）。
    #[test]
    fn bypass_missing_best_route_rejects_plan() {
        let err = bypass_routes_from_control_with(
            &[Ipv4Addr::from([10, 1, 1, 1])],
            |_| Ok(None),
        )
        .expect_err("no route must reject");
        assert_eq!(err.code, ERROR_NOT_FOUND);
    }

    /// `capture` 硬失败 → 错误传播（不吞）。
    #[test]
    fn bypass_capture_error_propagates() {
        let err = bypass_routes_from_control_with(
            &[Ipv4Addr::from([10, 1, 1, 1])],
            |_| Err(NativeError::from_win32(87, "capture boom")),
        )
        .expect_err("capture error must propagate");
        assert_eq!(err.code, 87);
    }

    /// 空 `control_bypass` → 空 bypass 行（不触发任何 `GetBestRoute2`）。
    #[test]
    fn empty_control_bypass_yields_empty_bypass_rows() {
        let rows = bypass_routes_from_control(&[]).expect("empty bypass");
        assert!(rows.is_empty());
    }

    /// 隧道路由行参数形状：网络/前缀 + on-link（`next_hop` 清空）+ 隧道 LUID +
    /// metric 1（**C2 G-③**：对齐 C++ `native_ip_config.cpp:793`——Wintun 路由
    /// 直挂隧道接口，网关式 + metric5 会让路由在另一 TUN 占默认路由时掉出活跃
    /// 选路）。
    #[test]
    fn tunnel_route_row_shape() {
        let route = Ipv4Route {
            network: Ipv4Addr::from([10, 0, 0, 0]),
            prefix_len: 24,
        };
        let row = tunnel_route_row(&route, 0x1234);
        assert_eq!(row.network, Ipv4Addr::from([10, 0, 0, 0]));
        assert_eq!(row.prefix_len, 24);
        assert_eq!(row.next_hop, Ipv4Addr::UNSPECIFIED);
        assert_eq!(row.interface_luid, 0x1234);
        assert_eq!(row.metric, TUNNEL_ROUTE_METRIC);
    }

    /// `tunnel_routes_from_plan` 逐条收集 `plan.ipv4_routes`（每条 on-link +
    /// metric 1，C2 G-③）。
    #[test]
    fn tunnel_routes_collect_per_plan_route() {
        let mut plan = plan_without_bypass();
        plan.ipv4_routes = vec![
            Ipv4Route {
                network: Ipv4Addr::from([10, 0, 0, 0]),
                prefix_len: 24,
            },
            Ipv4Route {
                network: Ipv4Addr::from([10, 1, 0, 0]),
                prefix_len: 16,
            },
        ];
        let rows = tunnel_routes_from_plan(&plan, 0x1234);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].network, Ipv4Addr::from([10, 1, 0, 0]));
        assert_eq!(rows[1].prefix_len, 16);
        assert_eq!(rows[1].interface_luid, 0x1234);
        // C2 G-③：每条隧道路由都是 on-link（next_hop 清空）+ metric 1。
        assert_eq!(rows[0].next_hop, Ipv4Addr::UNSPECIFIED);
        assert_eq!(rows[1].next_hop, Ipv4Addr::UNSPECIFIED);
        assert_eq!(rows[0].metric, TUNNEL_ROUTE_METRIC);
        assert_eq!(rows[1].metric, TUNNEL_ROUTE_METRIC);
    }

    /// `apply_plan_from_tunnel`（空 bypass 时不触发真实 syscall）组装完整跨族
    /// `ApplyPlan`：canonical family 顺序 Address→Mtu→Bypass→Routes→Dns、地址行、
    /// MTU、DNS；bypass 矢量保持空（无 syscall）。
    #[test]
    fn apply_plan_from_tunnel_assembles_full_plan_shape() {
        let plan = plan_without_bypass();
        let apply = apply_plan_from_tunnel(&plan, 0x1234).expect("apply plan");
        // TK1b：canonical 顺序插入 SystemProxy（bypass 之后、routes 之前）。
        assert_eq!(
            apply.steps,
            vec![
                FamilyStep::Address,
                FamilyStep::Mtu,
                FamilyStep::Bypass,
                FamilyStep::SystemProxy,
                FamilyStep::Routes,
                FamilyStep::Dns,
            ]
        );
        assert_eq!(
            apply.addresses,
            vec![IpAddressRow::new(
                Ipv4Addr::from([10, 0, 0, 1]),
                0x1234,
                24
            )]
        );
        assert_eq!(apply.mtu_v4, 1400);
        assert_eq!(apply.mtu_v6, None);
        assert!(apply.bypass.is_empty());
        assert_eq!(apply.tunnel_routes.len(), 1);
        // C2 G-③：隧道路由 on-link（next_hop 清空）+ metric 1。
        assert_eq!(apply.tunnel_routes[0].next_hop, Ipv4Addr::UNSPECIFIED);
        assert_eq!(apply.tunnel_routes[0].metric, TUNNEL_ROUTE_METRIC);
        assert_eq!(
            apply.dns,
            DnsSettings::new(vec!["1.1.1.1".to_string()], Vec::new())
        );
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
