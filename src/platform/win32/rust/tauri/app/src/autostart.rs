//! 开机自动运行（HKCU `Run` key）。
//!
//! 写当前用户侧注册表（无提权）：`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//! 值名 `EXV VPN` = 当前 exe 绝对路径。不带命令行参数——静默与否由 ui_prefs 的
//! `silent_startup` 决定（运行时读取），避免 Run key 与偏好文件两处漂移。
//!
//! 前端持久开关记录在 `ui-preferences.json` 的 `launch_at_login`（显示态）；
//! 注册表是执行真相源，两者由前端 toggle 同步写。

use windows::core::w;
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW,
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_VALUE_TYPE,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegOpenKeyExW,
};

/// HKCU Run 子键路径。
const RUN_SUBKEY: windows::core::PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
/// 本应用的 Run 值名。
pub const RUN_VALUE_NAME: windows::core::PCWSTR = w!("EXV VPN");

/// 测试可注入的值名入口：真实注册表 set/query/delete 后清理。
fn run_key() -> Result<HKEY, String> {
    let mut hkey = HKEY::default();
    // 安全注释：仅打开本应用自己的 HKCU Run 值；KEY_SET_VALUE|KEY_QUERY_VALUE
    // 均为用户自身权限，无提权。
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            RUN_SUBKEY,
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            None,
            &mut hkey,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("RegCreateKeyExW failed: {}", status.0));
    }
    Ok(hkey)
}

/// 当前进程 exe 绝对路径。
fn current_exe_path() -> Result<String, String> {
    std::env::current_exe()
        .map_err(|e| format!("current_exe failed: {e}"))?
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| "exe path is not valid UTF-8".to_string())
}

/// 设置/清除自启项。`enabled=true` 时写入 exe 路径；false 时删除值（不存在视为成功）。
///
/// # Errors
/// 注册表操作失败或 exe 路径不可解析。
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    set_autostart_with_value_name(RUN_VALUE_NAME, enabled)
}

/// [`set_autostart`] 的测试注入口：以指定值名驱动真注册表。
fn set_autostart_with_value_name(value_name: windows::core::PCWSTR, enabled: bool) -> Result<(), String> {
    if !enabled {
        let mut hkey = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                RUN_SUBKEY,
                Some(0),
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if status != ERROR_SUCCESS {
            // 键不存在 = 未自启，删除目标天然满足。
            return Ok(());
        }
        let status = unsafe { RegDeleteValueW(hkey, value_name) };
        let _ = unsafe { RegCloseKey(hkey) };
        if status == ERROR_SUCCESS || status == WIN32_ERROR(2) {
            // 2 = ERROR_FILE_NOT_FOUND（值不存在）——目标状态已达成。
            return Ok(());
        }
        return Err(format!("RegDeleteValueW failed: {}", status.0));
    }

    let exe = current_exe_path()?;
    let hkey = run_key()?;
    // 含结尾 NUL 的 UTF-16。
    let mut wide: Vec<u16> = exe.encode_utf16().collect();
    wide.push(0);
    let bytes = wide.len() * std::mem::size_of::<u16>();
    let status = unsafe {
        RegSetValueExW(
            hkey,
            value_name,
            Some(0),
            REG_SZ,
            Some(std::slice::from_raw_parts(
                wide.as_ptr().cast::<u8>(),
                bytes,
            )),
        )
    };
    let _ = unsafe { RegCloseKey(hkey) };
    if status != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW failed: {}", status.0));
    }
    Ok(())
}

/// 查询自启项是否已启用。
///
/// # Errors
/// 打开 Run 键失败（值缺失不算错）。
pub fn is_autostart_enabled() -> Result<bool, String> {
    is_autostart_enabled_with_value_name(RUN_VALUE_NAME)
}

fn is_autostart_enabled_with_value_name(value_name: windows::core::PCWSTR) -> Result<bool, String> {
    let mut hkey = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(HKEY_CURRENT_USER, RUN_SUBKEY, Some(0), KEY_QUERY_VALUE, &mut hkey)
    };
    if status != ERROR_SUCCESS {
        // 键不存在 = 未启用。
        return Ok(false);
    }
    let mut kind = REG_VALUE_TYPE::default();
    let mut bytes = 0u32;
    let status = unsafe {
        RegQueryValueExW(hkey, value_name, None, Some(&mut kind), None, Some(&mut bytes))
    };
    let _ = unsafe { RegCloseKey(hkey) };
    match status {
        ERROR_SUCCESS => Ok(kind == REG_SZ && bytes > 0),
        WIN32_ERROR(2) => Ok(false), // ERROR_FILE_NOT_FOUND
        other => Err(format!("RegQueryValueExW failed: {}", other.0)),
    }
}

// ---- Command ----

/// `autostart_set`：设置开机自动运行并回报结果（ok + 人类可读信息）。
#[tauri::command]
pub fn autostart_set(enabled: bool) -> Result<serde_json::Value, String> {
    set_autostart(enabled)?;
    let now_enabled = is_autostart_enabled().unwrap_or(!enabled);
    Ok(serde_json::json!({ "ok": now_enabled == enabled }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 每个真实注册表测试使用独立值名。Rust 默认并发执行测试；若共享一个值，某个
    // 测试的清理会删除另一个测试刚写入、尚待读取的值，导致 ERROR_FILE_NOT_FOUND。
    const ROUNDTRIP_TEST_VALUE: windows::core::PCWSTR = w!("EXV VPN __roundtrip_test_only__");
    const ABSENT_TEST_VALUE: windows::core::PCWSTR = w!("EXV VPN __absent_test_only__");
    const EXE_PATH_TEST_VALUE: windows::core::PCWSTR = w!("EXV VPN __exe_path_test_only__");

    #[test]
    fn enable_query_disable_roundtrip_on_real_registry() {
        // 前置：确保干净（上次异常残留时也成立）。
        let _ = set_autostart_with_value_name(ROUNDTRIP_TEST_VALUE, false);

        set_autostart_with_value_name(ROUNDTRIP_TEST_VALUE, true).expect("enable");
        assert!(is_autostart_enabled_with_value_name(ROUNDTRIP_TEST_VALUE).expect("query"));

        set_autostart_with_value_name(ROUNDTRIP_TEST_VALUE, false).expect("disable");
        assert!(!is_autostart_enabled_with_value_name(ROUNDTRIP_TEST_VALUE).expect("query after disable"));
    }

    #[test]
    fn disable_when_absent_is_ok() {
        let _ = set_autostart_with_value_name(ABSENT_TEST_VALUE, false);
        set_autostart_with_value_name(ABSENT_TEST_VALUE, false).expect("disable when absent is success");
        assert!(!is_autostart_enabled_with_value_name(ABSENT_TEST_VALUE).expect("query"));
    }

    #[test]
    fn enabled_value_points_at_current_exe() {
        set_autostart_with_value_name(EXE_PATH_TEST_VALUE, true).expect("enable");

        let mut hkey = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(HKEY_CURRENT_USER, RUN_SUBKEY, Some(0), KEY_QUERY_VALUE, &mut hkey)
        };
        assert_eq!(status, ERROR_SUCCESS);
        let mut buf = [0u16; 1024];
        let mut bytes = (buf.len() * 2) as u32;
        let mut kind = REG_VALUE_TYPE::default();
        let status = unsafe {
            RegQueryValueExW(
                hkey,
                EXE_PATH_TEST_VALUE,
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr().cast::<u8>()),
                Some(&mut bytes),
            )
        };
        let _ = unsafe { RegCloseKey(hkey) };
        assert_eq!(status, ERROR_SUCCESS);
        let stored = String::from_utf16_lossy(&buf[..(bytes as usize / 2)])
            .trim_end_matches('\0')
            .to_string();
        assert_eq!(stored, current_exe_path().expect("exe"));

        let _ = set_autostart_with_value_name(EXE_PATH_TEST_VALUE, false);
    }
}
