// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! CSTP/TLS 控制面 socket 出口绑定供给接缝（PRD G-④ / C3）。
//!
//! **C4 提升后本模块的供给实现已提升进生产**（`exv-vpn-win32-resource::vgdc_dns::
//! socket_binder_for_ifindex`）；本模块对 win32 供给作**薄重导出**（不 fork 两份），
//! acceptance 调用面保持 `socket_binder_for_ifindex` 稳定。
//!
//! 语义（IP_UNICAST_IF，网络字节序，绑定点 = TCP connect 之前）与依赖见
//! `exv-vpn-win32-resource::vgdc_dns::socket_binder_for_ifindex`。

pub use exv_vpn_win32_resource::vgdc_dns::socket_binder_for_ifindex;

// ---------------------------------------------------------------------------
// 机制测试（非 elevated）：真实 socket 上 setsockopt 的 rc=0 路径。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use exv_vpn_cstp::connector::SocketBinder;

    use super::*;
    use crate::direct_connect::find_physical_nics;

    /// 真实未连接 TcpSocket 上，物理网卡 ifindex 的 `IP_UNICAST_IF` 绑定必须返回
    /// `Ok`（rc=0；setsockopt 层面即证明绑定参数形态正确，无需建立连接）。
    ///
    /// 依赖宿主至少有一个物理网卡（`find_physical_nics`）；无物理网卡的宿主跳过断言。
    #[test]
    fn binder_accepts_detected_physical_nic_ifindex() {
        let nics = find_physical_nics().expect("物理网卡发现必须成功");
        let Some(nic) = nics.first() else {
            return; // 无物理网卡：不可验证，跳过（非失败）。
        };
        let binder: Option<Arc<SocketBinder>> = socket_binder_for_ifindex(nic.ifindex);
        let binder = binder.expect("非零 ifindex 必须产出绑定闭包");
        let socket = tokio::net::TcpSocket::new_v4().expect("创建未连接 socket");
        binder(&socket).expect("物理网卡 ifindex 的 IP_UNICAST_IF 绑定必须 rc=0");
    }

    /// ifindex == 0（未探测/无效）必须产出 `None`——调用方回退到不绑定默认路由。
    #[test]
    fn zero_ifindex_yields_none() {
        assert!(socket_binder_for_ifindex(0).is_none());
    }
}
