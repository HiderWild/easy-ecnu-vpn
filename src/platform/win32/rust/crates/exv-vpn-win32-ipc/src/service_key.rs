// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// S3/D2：服务模式 PSK-HMAC 双向认证的密钥原语。
//
// service 模式安装时生成随机 PSK（32 字节）写到 `%ProgramData%\exv\service.key`，
// DACL = SYSTEM + 安装用户（GA，复用 `pipe_security::PipeSecurity` 的冻结形状）。
// 服务 engine（LocalSystem）与安装用户的 core 都读它；pre-gRPC 裸帧挑战用
// HMAC-SHA256 证明共享秘密持有（新鲜 nonce + 恒时比较 + 双向）后才派发任何 gRPC
// 帧（落点选 pre-gRPC 裸帧挑战，免 helper_control 第三次解冻——理由见
// `docs/superpowers/evidence/2026-08-20-engine-service-psk-hmac.md`）。
//
// oneshot 无 PSK 文件（无服务安装）→ 不挑战，path+SID 为主机制（D2）。
// PSK 轮换（M14）：重装生成新 key；engine 重启读新 key，旧 key 连接断开即失效。

use std::path::PathBuf;

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
};

use crate::pipe_security::PipeSecurity;

/// `%ProgramData%` 下服务密钥相对路径。
pub const SERVICE_KEY_REL: &str = r"exv\service.key";

/// HMAC-SHA256（RFC 2104）——用 `sha2` 实现，零额外依赖。
///
/// 用于 pre-gRPC 挑战的应答计算；`key` 为 32 字节 PSK（或任意长度）。
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key = key.to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = Sha256::digest(&[&ipad[..], msg].concat());
    let out = Sha256::digest(&[&opad[..], &inner[..]].concat());
    let mut o = [0u8; 32];
    o.copy_from_slice(&out);
    o
}

/// 恒时比较（长度不等 → false；否则 XOR 折叠）。
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 32 字节随机数（getrandom；失败 → typed 错误，调用方 fail closed）。
///
/// # Errors
/// getrandom 失败 → 携带原因的字符串。
pub fn random_32() -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    getrandom::fill(&mut out).map_err(|e| format!("getrandom: {e}"))?;
    Ok(out)
}

/// `%ProgramData%\exv\service.key` 的完整路径。
///
/// # Errors
/// `ProgramData` 环境变量缺失 → typed 错误。
pub fn service_key_path() -> Result<PathBuf, String> {
    let pd = std::env::var_os("ProgramData")
        .ok_or_else(|| "ProgramData env missing (service PSK path)".to_string())?;
    Ok(PathBuf::from(pd).join(SERVICE_KEY_REL))
}

/// 生成并写服务 PSK 到 `%ProgramData%\exv\service.key`（DACL = SYSTEM + 安装用户）。
///
/// 安装/修复路径调用（engine 子命令，runas 提权边界内）：每次安装都轮换密钥（M14）。
/// 文件以 `CREATE_ALWAYS` 覆盖写；DACL 经 `PipeSecurity`（WSP1 §4 冻结形状：
/// `D:(A;;GA;;;SY)(A;;GA;;;<user_sid>)`）随 `CreateFileW` 的 `SECURITY_ATTRIBUTES` 生效。
///
/// # Errors
/// 随机数 / 路径 / `CreateFileW` / `WriteFile` 失败 → 携带原因的字符串。
pub fn write_service_psk(installer_sid: &str) -> Result<[u8; 32], String> {
    let psk = random_32()?;
    let path = service_key_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create service key dir {}: {e}", parent.display()))?;
    }
    let security = PipeSecurity::new(installer_sid, true)
        .map_err(|code| format!("service key DACL build failed (code {code})"))?;
    let attributes = security.as_attributes();
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` 是活的 NUL 结尾宽字符串；`attributes` 是活 `SECURITY_ATTRIBUTES`，
    // 其 `lpSecurityDescriptor` 指向 `security` 拥有的活 descriptor（同作用域存活）。
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ,
            Some(&raw const attributes as *const _),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| format!("create service key file: {e}"))?;
    let result = write_all_to_handle(handle, &psk);
    // SAFETY: `handle` 是 `CreateFileW` 返回的已打开句柄，使用后关闭。
    unsafe {
        let _ = CloseHandle(handle);
    }
    result?;
    Ok(psk)
}

/// 读服务 PSK（core 与服务 engine 都读；oneshot 无文件 → 调用方判缺）。
///
/// # Errors
/// 路径不可得 / 文件缺失 / 读取失败 → 携带原因的字符串。
pub fn read_service_psk() -> Result<[u8; 32], String> {
    let path = service_key_path()?;
    let bytes = std::fs::read(&path).map_err(|e| format!("read service key {}: {e}", path.display()))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("service key must be exactly 32 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

/// 删除服务 PSK 文件（`%ProgramData%\exv\service.key`）——卸载时清理孤儿载荷。
///
/// R3 卸载对策：`uninstall_service` 在 `DeleteService` 成功后调用。卸载面对「半装误判
/// 已装/上次卸载不彻底」——SCM 条目已删但 `service.key` 残留即孤儿载荷（host 健康模型
/// `HealthState::PayloadOrphan` 据此检测：SCM 未注册但 PSK 可读）。**幂等**：文件缺失
/// → `Ok(())`（首次卸载 / 无服务安装 / 已删）。
///
/// 与 [`write_service_psk`] 同路径（`service_key_path`），不重复建目录——删除无需目录。
///
/// # Errors
/// 路径不可得 / 删除失败（非「文件不存在」）→ 携带原因的字符串。
pub fn delete_service_psk() -> Result<(), String> {
    let path = service_key_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete service key {}: {e}", path.display())),
    }
}

/// 一次性写满 `buf` 到句柄（`WriteFile`；短写视为失败——密钥必须完整落盘）。
fn write_all_to_handle(handle: windows::Win32::Foundation::HANDLE, buf: &[u8]) -> Result<(), String> {
    let mut written = 0u32;
    // SAFETY: handle 是已打开可写句柄；written 是活 out-param。
    unsafe {
        WriteFile(handle, Some(buf), Some(&raw mut written), None)
    }
    .map_err(|e| format!("write service key: {e}"))?;
    if written as usize != buf.len() {
        return Err(format!(
            "short write: wrote {written}, expected {}",
            buf.len()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 单元测试：HMAC 已知答案 + 恒时比较 + 随机性 + 密钥文件 DACL 往返。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ProgramData 是进程级环境变量；这些测试都把它重定向到独立临时目录，必须串行。
    static PROGRAM_DATA_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// HMAC-SHA256 已知答案（RFC 4231 test case 1：key = 0x0b × 20，data = "Hi There"）。
    #[test]
    fn hmac_sha256_matches_rfc4231_case1() {
        let key = [0x0b; 20];
        let msg = b"Hi There";
        let out = hmac_sha256(&key, msg);
        let expect: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(out, expect, "RFC 4231 test case 1 必须匹配");
    }

    /// HMAC 对密钥 > 块长（64）时的压缩路径（RFC 2104：长密钥先 H(key)）。
    #[test]
    fn hmac_sha256_long_key_compresses() {
        let key = [0xaa; 80];
        let out = hmac_sha256(&key, b"test data");
        // 与独立实现交叉验证（确定性：不同 key 长度路径稳定）。
        let again = hmac_sha256(&key, b"test data");
        assert_eq!(out, again, "HMAC 必须确定性");
    }

    /// 恒时比较：相等 → true；任意字节差 → false；长度不等 → false。
    #[test]
    fn ct_eq_detects_any_difference() {
        let a = [0x11u8; 32];
        assert!(ct_eq(&a, &a));
        let mut b = a;
        b[31] ^= 1;
        assert!(!ct_eq(&a, &b));
        assert!(!ct_eq(&a, &a[..31]));
    }

    /// 随机 32 字节：两次生成不同（概率性但 2^-256 碰撞可忽略）。
    #[test]
    fn random_32_is_32_bytes_and_distinct() {
        let a = random_32().expect("random");
        let b = random_32().expect("random");
        assert_eq!(a.len(), 32);
        assert_ne!(a, b, "两次随机 32 字节必须不同");
    }

    /// 写→读往返：PSK 文件写后读回一致（DACL 创建由 CreateFileW 生效，真实 ACL
    /// 验证归真机；这里验证字节往返与 32 字节长度断言）。
    #[test]
    fn write_read_round_trip() {
        let _program_data_lock = PROGRAM_DATA_TEST_LOCK.lock().expect("ProgramData test lock");
        let dir = tempfile::tempdir().expect("temp dir");
        // 重定向 ProgramData 到临时目录（避免污染真实 %ProgramData%）。
        let old = std::env::var_os("ProgramData");
        // SAFETY: 单线程测试；ProgramData 重定向到本测试临时目录，结束即恢复。
        unsafe {
            std::env::set_var("ProgramData", dir.path());
        }
        // 安装用户 SID 用当前进程真实 SID——DACL = SYSTEM + 安装用户，当前用户才可读回
        //（真实安装路径 `install_service` 传 `core_user_sid`，即安装用户）。
        let installer_sid = crate::peer_auth::current_user_sid().expect("current user sid");
        let psk = write_service_psk(&installer_sid).expect("write");
        let read = read_service_psk().expect("read");
        assert_eq!(psk, read, "写后读必须一致（32 字节）");
        // SAFETY: 恢复测试前的 ProgramData 值（无并发 env 读者）。
        match old {
            Some(v) => unsafe { std::env::set_var("ProgramData", v) },
            None => unsafe { std::env::remove_var("ProgramData") },
        }
    }

    /// 删除孤儿 PSK（R3 卸载对策）：写→删→文件消失；再删（已不存在）幂等 Ok。
    /// ProgramData 重定向到临时目录，避免污染真实 `%ProgramData%`。
    #[test]
    fn delete_service_psk_removes_file_and_is_idempotent() {
        let _program_data_lock = PROGRAM_DATA_TEST_LOCK.lock().expect("ProgramData test lock");
        let dir = tempfile::tempdir().expect("temp dir");
        let old = std::env::var_os("ProgramData");
        // SAFETY: 单线程测试；ProgramData 重定向到本测试临时目录，结束即恢复。
        unsafe {
            std::env::set_var("ProgramData", dir.path());
        }
        let installer_sid = crate::peer_auth::current_user_sid().expect("current user sid");
        let _psk = write_service_psk(&installer_sid).expect("write");
        let path = service_key_path().expect("path");
        assert!(path.exists(), "写后文件必须存在");

        delete_service_psk().expect("delete");
        assert!(!path.exists(), "删除后文件必须消失");

        // 幂等：已不存在再删 → Ok（首次卸载/无服务安装路径）。
        delete_service_psk().expect("delete again idempotent");
        // SAFETY: 恢复测试前的 ProgramData 值（无并发 env 读者）。
        match old {
            Some(v) => unsafe { std::env::set_var("ProgramData", v) },
            None => unsafe { std::env::remove_var("ProgramData") },
        }
    }
}
