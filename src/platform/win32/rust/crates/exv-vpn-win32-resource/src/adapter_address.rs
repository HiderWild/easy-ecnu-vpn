// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。

//! 读取指定适配器当前的 IPv4 单播地址。
//!
//! 这是只读观测接口：不缓存、不创建接口、不修改地址。连接页的“校内地址”
//! 使用它读取实际 EXV Wintun 适配器的当前地址；未连接或地址尚未完成分配时
//! 返回 `Ok(None)`，而不是用配置占位值冒充真实地址。

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET, SOCKET_ADDRESS};

const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// 按适配器 FriendlyName 读取第一个 IPv4 单播地址。
///
/// # Errors
///
/// `GetAdaptersAddresses` 枚举失败时返回错误；找不到适配器或适配器没有 IPv4
/// 地址时返回 `Ok(None)`。
pub fn first_ipv4_for_adapter(adapter_name: &str) -> Result<Option<Ipv4Addr>, String> {
    let adapter_name = adapter_name.trim();
    if adapter_name.is_empty() {
        return Ok(None);
    }

    let mut size: u32 = 0;
    // SAFETY: 首次调用只查询缓冲区尺寸；指针参数均为 None，size 由系统写入。
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_INET.0),
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            None,
            &raw mut size,
        )
    };
    if rc != 0 && rc != ERROR_BUFFER_OVERFLOW {
        return Err(format!("GetAdaptersAddresses size query failed: {rc}"));
    }

    let mut buffer = vec![0u64; size as usize / 8 + 2];
    let ptr = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    #[allow(clippy::cast_possible_truncation)]
    let mut out_size = (buffer.len() * 8) as u32;
    // SAFETY: buffer 按 API 返回尺寸分配并按 u64 对齐；调用期间 buffer 保持存活。
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_INET.0),
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            Some(ptr),
            &raw mut out_size,
        )
    };
    if rc != 0 {
        return Err(format!("GetAdaptersAddresses failed: {rc}"));
    }

    let mut current = ptr;
    while !current.is_null() {
        // SAFETY: current 来自系统填充的、以 Next 串联的适配器链表。
        let adapter = unsafe { &*current };
        // SAFETY: FriendlyName 是系统提供的以 NUL 结尾的宽字符串。
        let name = unsafe { adapter.FriendlyName.to_string() }.unwrap_or_default();
        if name.eq_ignore_ascii_case(adapter_name) {
            return Ok(first_ipv4_unicast(adapter));
        }
        current = adapter.Next;
    }

    Ok(None)
}

fn first_ipv4_unicast(adapter: &IP_ADAPTER_ADDRESSES_LH) -> Option<Ipv4Addr> {
    let mut current = adapter.FirstUnicastAddress;
    while !current.is_null() {
        // SAFETY: FirstUnicastAddress/Next 由 GetAdaptersAddresses 返回且当前节点非空。
        let unicast = unsafe { &*current };
        if let Some(address) = ipv4_of(&unicast.Address) {
            return Some(address);
        }
        current = unicast.Next;
    }
    None
}

fn ipv4_of(address: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if address.lpSockaddr.is_null() {
        return None;
    }
    // SAFETY: AF_INET 地址由系统填充，SOCKET_ADDRESS 指向兼容的 SOCKADDR_INET。
    let inet = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_INET>() };
    if unsafe { inet.si_family } != AF_INET {
        return None;
    }
    // SAFETY: AF_INET 分支下 Ipv4.sin_addr 有效；Windows 小端内存布局用 to_le_bytes
    // 还原用户可读的 IPv4 八位组顺序。
    let octets = unsafe { inet.Ipv4.sin_addr.S_un.S_addr }.to_le_bytes();
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_adapter_name_is_a_non_effectful_miss() {
        assert_eq!(
            first_ipv4_for_adapter("  ").expect("blank name is valid"),
            None
        );
    }
}
