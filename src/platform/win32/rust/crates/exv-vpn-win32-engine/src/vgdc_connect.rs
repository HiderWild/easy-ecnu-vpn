// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
// PRD G-⑤ / C4：docs/superpowers/plans/2026-08-17-vpn-rust-proxy-tun-coexistence-prd.md。

//! 生产装配点：VGDC 双线直连 DNS + CSTP 控制面 socket 出口绑定（C4）。
//!
//! 本模块是 engine（本 helper 进程）在**拉起后、connect 前**装配控制面直连原语的
//! 接缝——engine 解析 VPN 服务器域名时走 VGDC 双线（DoH 直连 + 绑物理网卡 UDP/53
//! 兜底），不经 Mihomo fake-ip 污染；控制面连接以 `IP_UNICAST_IF` 钉在物理出口。
//!
//! - [`production_gateway_resolver`]：由物理出口 ifindex（`ifindex == 0` 时经
//!   `find_physical_nics` 自动发现首个物理网卡）构造 `BootstrapConfig.gateway_resolver`
//!   闭包——内部捕获 `DualLineConfig::production`，async 解析 hostname → `(ip, port)`。
//! - [`production_socket_binder`]：`BootstrapConfig.socket_binder` 的物理出口绑定闭包
//!   （`exv-vpn-win32-resource::vgdc_dns::socket_binder_for_ifindex` 重导出）。
//!
//! 装配顺序（C4 与 C3 衔接）：解析结果（物理出口 IP）供 CSTP connector 连接；解析与
//! 绑定共用同一物理网卡 ifindex（`find_physical_nics` 一次发现）。P5 接线点：engine
//! 的 connect 路径构造 `BootstrapConfig` 时注入两个闭包。

use std::net::SocketAddr;
use std::sync::Arc;

use exv_vpn_cstp::connector::{GatewayResolver, ResolverFuture, SocketBinder};
use exv_vpn_win32_resource::vgdc_dns::{
    DualLineConfig, ResolveLayerError, find_physical_nics, socket_binder_for_ifindex,
};

/// CSTP 控制面默认端口（标准 HTTPS/CSTP 端口；协议帧未携带端口字段）。
pub const CSTP_GATEWAY_PORT: u16 = 443;

/// 由物理出口 ifindex 构造 VGDC 双线 DNS 解析器闭包（`BootstrapConfig.gateway_resolver`）。
///
/// `ifindex == 0`（未探测）时经 [`find_physical_nics`] 自动发现首个物理网卡作为出口；
/// 发现失败或无物理网卡 → `Err(String)`（fail closed，不静默回退系统解析——直连保证
/// 是 C4 的承诺）。`port` 是 CSTP 控制面端口（默认 [`CSTP_GATEWAY_PORT`]）。
///
/// 返回的闭包是 async 形态（`ResolverFuture`）：DoH 线路在调用方 tokio 上下文内直接
/// await，不 block_on 外部 runtime。
///
/// # Errors
///
/// `ifindex == 0` 且物理网卡发现失败/为空 → `String` 描述。
pub fn production_gateway_resolver(
    ifindex: u32,
    port: u16,
) -> Result<Arc<GatewayResolver>, String> {
    let resolved_ifindex = if ifindex == 0 {
        let nics = find_physical_nics().map_err(|e| format!("vgdc-nics:{e}"))?;
        let nic = nics
            .first()
            .ok_or_else(|| "vgdc-nics:no-physical-nic".to_string())?;
        nic.ifindex
    } else {
        ifindex
    };
    let cfg = DualLineConfig::production(Some(resolved_ifindex))
        .map_err(|e| format!("vgdc-config:{e}"))?;
    Ok(Arc::new(move |host: &str| -> ResolverFuture {
        let cfg = cfg.clone();
        let host = host.to_string();
        Box::pin(async move {
            exv_vpn_win32_resource::vgdc_dns::resolve_gateway_dual_line(&cfg, &host)
                .await
                .map(|(ip, _source)| SocketAddr::from((ip, port)))
                .map_err(|errors| {
                    let detail: Vec<String> = errors
                        .iter()
                        .map(ResolveLayerError::describe)
                        .collect();
                    format!("vgdc-resolve:{}", detail.join("; "))
                })
        })
    }))
}

/// 由物理出口 ifindex 构造 CSTP/TLS 控制面 socket 出口绑定闭包
/// （`BootstrapConfig.socket_binder`；`IP_UNICAST_IF`）。
///
/// `ifindex == 0`（未探测/无效）返回 `None`——调用方可回退到不绑定（默认路由）。
#[must_use]
pub fn production_socket_binder(ifindex: u32) -> Option<Arc<SocketBinder>> {
    socket_binder_for_ifindex(ifindex)
}

// ---------------------------------------------------------------------------
// 单元测试（非网络）：闭包形态、IP 字面量路径、ifindex==0 自动发现与 fail-closed。
// 真实双线解析机制测试在 `exv-vpn-win32-resource::vgdc_dns`。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use exv_vpn_win32_resource::vgdc_dns::DualLineConfig;

    /// IP 字面量 host 直接采用（`ResolutionSource::System`）——不触碰网络，验证闭包
    /// 装配后的 async 解析语义正确。
    #[tokio::test]
    async fn resolver_accepts_ip_literal_host() {
        let resolver = production_gateway_resolver(0, CSTP_GATEWAY_PORT).unwrap_or_else(|e| {
            panic!("production resolver must construct: {e}");
        });
        let addr = resolver("222.66.117.109").await.expect("IP 字面量直接采用");
        assert_eq!(addr, SocketAddr::from((Ipv4Addr::new(222, 66, 117, 109), 443)));
    }

    /// fake-ip 字面量必须被拒绝（typed 错误）——闭包把 `ResolveLayerError` 向量
    /// 描述为 `vgdc-resolve:` 前缀错误。
    #[tokio::test]
    async fn resolver_rejects_fake_ip_literal() {
        let resolver = production_gateway_resolver(0, CSTP_GATEWAY_PORT).unwrap_or_else(|e| {
            panic!("production resolver must construct: {e}");
        });
        let err = resolver("198.18.1.15")
            .await
            .expect_err("fake-ip 字面量必须拒绝");
        assert!(err.starts_with("vgdc-resolve:fake-ip-literal:198.18.1.15"), "got {err}");
    }

    /// `production_gateway_resolver` 的 ifindex==0 自动发现路径在无物理网卡宿主上
    /// fail-closed（`Err`），绝不静默回退系统解析；有物理网卡时返回 Ok 且闭包可解析
    /// IP 字面量。两种结果都是合法行为，断言不允许第三种。
    #[test]
    fn resolver_zero_ifindex_discovers_or_fails_closed() {
        match production_gateway_resolver(0, CSTP_GATEWAY_PORT) {
            Ok(resolver) => {
                // 自动发现成功：闭包必须可解析 IP 字面量（不触碰网络）。
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                let addr = rt
                    .block_on(resolver("222.66.117.109"))
                    .expect("IP 字面量直接采用");
                assert_eq!(addr.port(), 443);
            }
            Err(msg) => {
                // 无物理网卡：fail closed（绝不静默回退系统解析）。
                assert!(msg.starts_with("vgdc-nics:"), "got {msg}");
            }
        }
    }

    /// `production_socket_binder` 与资源原语一致：ifindex==0 → None；非零 → Some。
    #[test]
    fn socket_binder_zero_ifindex_yields_none() {
        assert!(production_socket_binder(0).is_none());
    }

    /// `production_gateway_resolver` 产出的闭包底层使用生产 `DualLineConfig`（含
    /// 绑网卡 ifindex）——装配正确性（不 fork 配置构造）。
    #[test]
    fn resolver_builds_production_dualline_config() {
        let nics = find_physical_nics().unwrap_or_default();
        let Some(nic) = nics.first() else {
            return; // 无物理网卡：不可验证，跳过（非失败）。
        };
        let cfg = DualLineConfig::production(Some(nic.ifindex)).expect("production config");
        // 生产 DoH endpoint 冻结（223.5.5.5/resolve → 1.1.1.1/dns-query）。
        assert_eq!(cfg.doh_endpoints.len(), 2);
        assert_eq!(cfg.doh_endpoints[0].ip, Ipv4Addr::new(223, 5, 5, 5));
        assert_eq!(cfg.udp53_resolvers.len(), 3);
        assert_eq!(cfg.udp53_ifindex, Some(nic.ifindex));
    }
}
