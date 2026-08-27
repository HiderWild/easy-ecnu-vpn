//! EXV AUMID 身份注册：让系统 toast 以「EXV」身份发出。
//!
//! Windows 的 `ToastNotificationManager::CreateToastNotifierWithId(aumid)` 要求该 aumid
//! 已在系统「注册」。标准注册方式 = 在 Start menu 放一个带 `System.AppUserModelID` 属性
//! （值 = AUMID）的快捷方式，指向应用 exe；未注册的 aumid 会退回系统默认身份——历史上本
//! 项目复用 PowerShell 的 AUMID（toast 名头因此显示「Windows PowerShell」）。
//!
//! 本模块在应用启动时（[`ensure_toast_identity_registered`]）幂等地确保该快捷方式存在且
//! 属性正确：
//!   * 路径与安装器一致：`<Programs>\EXV\EXV.lnk`（见
//!     `src/platform/win32/windows_setup_rust/shortcuts.cpp::CreateStartMenuShortcuts`）；
//!   * 安装器当前创建的快捷方式不带 AppUserModelID，故这里按需补写/修复（幂等）；
//!   * 已存在且 AppUserModelID 已正确时跳过，不覆盖已有快捷方式；
//!   * 顺带把嵌入的 EXV 图标缓存到状态目录，供 toast appLogoOverride 使用（可选增强，
//!     失败仅缺图标，不影响身份）。

use std::path::{Path, PathBuf};

use windows::core::{Interface, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
use windows::Win32::System::Com::StructuredStorage::{
    PROPVARIANT, PropVariantClear,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, IPersistFile, STGM_READ,
};
use windows::Win32::System::Variant::VT_LPWSTR;
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{
    FOLDERID_Programs, IShellLinkW, KNOWN_FOLDER_FLAG, SHGetKnownFolderPath, ShellLink,
};

/// 本应用注册的 AUMID（与 `tauri.conf.json` 的 `identifier` 一致）。
pub const AUMID: &str = "com.exv.vpn.desktop";
/// Start menu 快捷方式相对 Programs 的路径（与安装器 `shortcuts.cpp` 布局一致）。
const START_MENU_REL_PATH: &str = "EXV\\EXV.lnk";
/// 状态目录里缓存的 toast 图标文件名（嵌入的 icon.png 拷贝，供 appLogoOverride 引用）。
const TOAST_ICON_FILE: &str = "toast-icon.png";

/// 应用启动时调用：幂等确保 Start menu 快捷方式带本应用 AppUserModelID，并缓存 toast 图标。
/// 任一步失败只记日志（通知仍走 toast → 托盘气泡回退链），不阻断启动。
pub fn ensure_toast_identity_registered() {
    ensure_toast_icon();
    if let Err(err) = ensure_registered_impl() {
        tracing::warn!(
            target: "exv.toast",
            "toast AUMID shortcut registration failed: {err}"
        );
    }
}

/// 已缓存的 toast 图标 file:// URI；图标不可用时返回 None（toast 不绑图标也能显示）。
pub fn toast_icon_uri() -> Option<String> {
    let path = toast_icon_path()?;
    path.exists().then(|| file_uri(&path))
}

fn ensure_registered_impl() -> Result<(), String> {
    init_com()?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let link_path = start_menu_shortcut_path()?;
    // 幂等：已注册且属性正确则跳过（避免每次启动重写快捷方式）。
    if link_path.exists() {
        if read_aumid(&link_path).as_deref() == Some(AUMID) {
            return Ok(());
        }
    }
    write_shortcut(&link_path, &exe)
}

/// 把本线程初始化为 apartment 线程（重复初始化/线程模式不同都视为可用，同 C++ `EnsureComApartment`）。
fn init_com() -> Result<(), String> {
    let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if hr == S_OK || hr == S_FALSE || hr == RPC_E_CHANGED_MODE {
        return Ok(());
    }
    Err(format!("CoInitializeEx failed: {hr}"))
}

/// `<Programs>\EXV\EXV.lnk`（FOLDERID_Programs = `%APPDATA%\Microsoft\Windows\Start Menu\Programs`）。
fn start_menu_shortcut_path() -> Result<PathBuf, String> {
    let ptr = unsafe { SHGetKnownFolderPath(&FOLDERID_Programs, KNOWN_FOLDER_FLAG(0), None) }
        .map_err(|e| format!("SHGetKnownFolderPath(FOLDERID_Programs) failed: {e}"))?;
    let dir = unsafe { ptr.to_string() }
        .map_err(|e| format!("FOLDERID_Programs path decode failed: {e}"))?;
    unsafe { CoTaskMemFree(Some(ptr.as_ptr().cast())) };
    if dir.is_empty() {
        return Err("FOLDERID_Programs resolved to empty path".into());
    }
    Ok(PathBuf::from(dir).join(START_MENU_REL_PATH))
}

/// 创建/修复快捷方式：指向 exe、图标取 exe，并写 `System.AppUserModelID` = [`AUMID`]。
fn write_shortcut(link_path: &Path, exe: &Path) -> Result<(), String> {
    let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
        .map_err(|e| format!("CoCreateInstance(ShellLink) failed: {e}"))?;

    let exe_str = exe.to_string_lossy();
    unsafe {
        link.SetPath(&HSTRING::from(exe_str.as_ref()))
            .map_err(|e| format!("IShellLinkW::SetPath failed: {e}"))?;
        if let Some(dir) = exe.parent() {
            link.SetWorkingDirectory(&HSTRING::from(dir.to_string_lossy().as_ref()))
                .map_err(|e| format!("IShellLinkW::SetWorkingDirectory failed: {e}"))?;
        }
        link.SetIconLocation(&HSTRING::from(exe_str.as_ref()), 0)
            .map_err(|e| format!("IShellLinkW::SetIconLocation failed: {e}"))?;
        link.SetDescription(&HSTRING::from("EXV"))
            .map_err(|e| format!("IShellLinkW::SetDescription failed: {e}"))?;
    }

    let store: IPropertyStore = link
        .cast()
        .map_err(|e| format!("QueryInterface IPropertyStore failed: {e}"))?;
    set_aumid_property(&store, AUMID)?;
    drop(store);
    let persist: IPersistFile = link
        .cast()
        .map_err(|e| format!("QueryInterface IPersistFile failed: {e}"))?;
    if let Some(parent) = link_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create shortcut dir failed: {e}"))?;
    }
    unsafe {
        persist
            .Save(&HSTRING::from(link_path.to_string_lossy().as_ref()), true)
            .map_err(|e| format!("IPersistFile::Save failed: {e}"))?;
    }
    Ok(())
}

/// 读既有快捷方式的 AppUserModelID（未设置/非字符串返回 None）。
fn read_aumid(link_path: &Path) -> Option<String> {
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        let persist: IPersistFile = link.cast().ok()?;
        let wide: Vec<u16> = link_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        persist.Load(PCWSTR(wide.as_ptr()), STGM_READ).ok()?;
        let store: IPropertyStore = link.cast().ok()?;
        let mut propvar = store.GetValue(&PKEY_AppUserModel_ID).ok()?;
        let result = if propvar.Anonymous.Anonymous.vt == VT_LPWSTR {
            let ptr = propvar.Anonymous.Anonymous.Anonymous.pwszVal;
            if ptr.is_null() {
                None
            } else {
                ptr.to_string().ok()
            }
        } else {
            None
        };
        let _ = PropVariantClear(&mut propvar);
        result
    }
}

/// 给快捷方式属性存储写 `System.AppUserModelID` 并 Commit。
fn set_aumid_property(store: &IPropertyStore, value: &str) -> Result<(), String> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    // PROPVARIANT 以 zeroed 初始化再逐字段赋值——手写嵌套 union 构造在 windows crate
    // 的 ManuallyDrop 布局下有 ABI 风险（实测触发 ntdll 堆损坏 c0000374）。zeroed
    // 后经 addr_of_mut 写入 vt 与 pwszVal，是官方 unsafe 路径，避免手拼 union 位。
    // pwszVal 指向的宽字符串：IPropertyStore::SetValue 同步消费后仍以 Box::leak 保活
    // 到进程结束——避免窄存活期（函数返回即 drop）与 COM 延迟引用叠加造成的悬垂/堆损坏。
    let wide = Box::leak(Box::new(wide)).as_mut_slice();
    let mut propvar: PROPVARIANT = unsafe { core::mem::zeroed() };
    unsafe {
        let inner = core::ptr::addr_of_mut!(propvar.Anonymous.Anonymous)
            .cast::<windows::Win32::System::Com::StructuredStorage::PROPVARIANT_0_0>();
        (*inner).vt = VT_LPWSTR;
        (*inner).Anonymous.pwszVal = PWSTR(wide.as_mut_ptr());
    }
    unsafe {
        store
            .SetValue(&PKEY_AppUserModel_ID, &propvar)
            .map_err(|e| format!("IPropertyStore::SetValue(AppUserModelID) failed: {e}"))?;
        store
            .Commit()
            .map_err(|e| format!("IPropertyStore::Commit failed: {e}"))?;
    }
    Ok(())
}

/// 状态目录里缓存的 toast 图标路径 `<LOCALAPPDATA>\EXV\profile\default\toast-icon.png`。
fn toast_icon_path() -> Option<PathBuf> {
    crate::ui_prefs::ui_state_dir().map(|dir| dir.join(TOAST_ICON_FILE))
}

/// 幂等缓存 toast 图标（嵌入 icon.png → 状态目录）。失败静默：图标只是增强。
fn ensure_toast_icon() {
    let Some(path) = toast_icon_path() else { return };
    if path.exists() {
        return;
    }
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    if std::fs::write(&path, include_bytes!("../icons/icon.png")).is_err() {
        return;
    }
}

/// 本地路径 → `file:///C:/...` URI（toast `<image>` 需要 file 协议绝对路径）。
fn file_uri(path: &Path) -> String {
    let mut s = path.to_string_lossy().replace('\\', "/");
    while s.starts_with('/') {
        s.remove(0);
    }
    format!("file:///{s}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aumid_matches_tauri_identifier() {
        assert_eq!(AUMID, "com.exv.vpn.desktop");
    }

    #[test]
    fn aumid_no_longer_reuses_powershell_identity() {
        // R8 回归护栏：旧实现用 PowerShell 的 AUMID（toast 名头显示「Windows PowerShell」）。
        assert_ne!(
            AUMID,
            r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
        );
    }

    #[test]
    fn start_menu_layout_matches_installer() {
        // 与 windows_setup_rust/shortcuts.cpp 的 `<Programs>\EXV\EXV.lnk` 保持一致，
        // 保证安装器与运行时注册落在同一文件、不产生双份快捷方式。
        assert_eq!(START_MENU_REL_PATH, "EXV\\EXV.lnk");
    }

    #[test]
    fn file_uri_uses_forward_slashes() {
        assert_eq!(file_uri(Path::new(r"C:\Users\Tom\AppData\Local\EXV\a b.png")),
            "file:///C:/Users/Tom/AppData/Local/EXV/a b.png");
    }
}
