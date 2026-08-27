//! 前端自有设置（UI preferences）的持久化与 Tauri Command。
//!
//! ## 边界切割（2026-08-23 拍板）
//!
//! 设置分两域，互不越界：
//!   * **core 配置**（`server/username/password/remember_password/routes/user_agent/mtu`）：
//!     走既有 `config_get/config_set`（core 权威），本模块绝不触碰。
//!   * **前端自有设置**（纯 UI 行为偏好）：存本模块文件，修改**不走 core config**。
//!
//! 字段名照抄 C++ 宿主偏好契约
//! （`src/contracts/generated/product_semantic_contract.hpp` HostPreferences 域：
//! `close_preference / minimize_to_tray_on_connect / launch_at_login / silent_startup /
//! connection_state_notifications` + core 侧 Config 同名的 `auto_connect_on_launch`），
//! 保证用户升级时 schema 同源、语义连续。
//!
//! 刻意排除的旧契约字段：`theme/accent/minimal_mode`（= 现前端外观域，持久在 WebView2
//! localStorage `exv.ui.appearance`——避免双真相源；本轮不动）；`service_install_prompt_seen`
//! （当前无该提示流）；`dtls_mode`（gate 禁止）。
//!
//! ## 存储位置（升级无感）
//!
//! `%LOCALAPPDATA%\EXV\profile\default\ui-preferences.json` —— 与 C++ 壳进程状态目录同源
//! （复刻 `src/platform/win32/path_utils.cpp::profile_root_for_home` +
//! `default_config_dir_for_home` 推导链）。首次读取时若存在旧 C++ 壳的
//! `close-preference.json` 则一次性导入其关闭偏好并立即落盘（幂等：仅当目标文件不存在）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::State;

/// 状态目录子链：`<LOCALAPPDATA>\EXV\profile\default`（与 C++ 壳一致）。
const PROFILE_ROOT: &str = "EXV";
const PROFILE_SUBDIR: &str = "profile";
const DEFAULT_PROFILE: &str = "default";
/// 本模块持久化文件名。
const PREFS_FILE: &str = "ui-preferences.json";
/// 旧 C++ 壳进程的关闭偏好文件（一次性导入源）。
const LEGACY_CLOSE_PREF_FILE: &str = "close-preference.json";

/// 关闭按钮行为的合法值（与 C++ 契约 `close_preference` 枚举一致）。
pub const CLOSE_PREFERENCE_VALUES: [&str; 3] = ["smart", "tray", "quit"];
/// `close_preference` 缺省值：智能最小化（误关保护宽限）。
pub const DEFAULT_CLOSE_PREFERENCE: &str = "smart";

// ---- wire 结构（snake_case 键照抄契约；全 Option 以区分「未设置」与默认值，
//      序列化时 None 跳过，读入时缺键回落默认——向前兼容旧文件。） ----

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct UiPreferences {
    /// 关闭按钮行为："smart" | "tray" | "quit"。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_preference: Option<String>,
    /// 连接成功后自动隐藏窗口到托盘。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimize_to_tray_on_connect: Option<bool>,
    /// 开机自动运行（HKCU Run key 的持久开关记录；Run key 由 autostart.rs 写）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_at_login: Option<bool>,
    /// 启动静默：所有启动方式都不弹窗，仅托盘驻留。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub silent_startup: Option<bool>,
    /// 连接/断开时托盘气泡通知。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state_notifications: Option<bool>,
    /// 应用启动且空闲时自动发起连接。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_connect_on_launch: Option<bool>,
}

impl UiPreferences {
    /// 读出时的有效值视图（None → 默认；非法 close_preference → 默认 smart）。
    fn effective(&self) -> Self {
        Self {
            close_preference: Some(
                self.close_preference
                    .as_deref()
                    .filter(|v| CLOSE_PREFERENCE_VALUES.contains(&v))
                    .unwrap_or(DEFAULT_CLOSE_PREFERENCE)
                    .to_string(),
            ),
            minimize_to_tray_on_connect: Some(self.minimize_to_tray_on_connect.unwrap_or(false)),
            launch_at_login: Some(self.launch_at_login.unwrap_or(false)),
            silent_startup: Some(self.silent_startup.unwrap_or(false)),
            connection_state_notifications: Some(
                self.connection_state_notifications.unwrap_or(false),
            ),
            auto_connect_on_launch: Some(self.auto_connect_on_launch.unwrap_or(false)),
        }
    }
}

// ---- 路径推导（测试可注入目录）----

fn local_app_data() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    // 与 C++ `get_windows_local_app_data_home` 兜底一致：<USERPROFILE>\AppData\Local。
    let profile = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(profile).join("AppData").join("Local"))
}

/// 产品状态目录（C++ 壳同源）：`<LOCALAPPDATA>\EXV\profile\default`。
///
/// 测试经 [`ui_prefs_path_for`] 注入任意根目录；生产调用方用本函数。
#[must_use]
pub fn ui_state_dir() -> Option<PathBuf> {
    Some(local_app_data()?.join(PROFILE_ROOT).join(PROFILE_SUBDIR).join(DEFAULT_PROFILE))
}

/// `<dir>/ui-preferences.json`。
#[must_use]
pub fn ui_prefs_path_for(dir: &Path) -> PathBuf {
    dir.join(PREFS_FILE)
}

/// 旧 C++ 壳关闭偏好路径 `<dir>/close-preference.json`。
#[must_use]
fn legacy_close_pref_path_for(dir: &Path) -> PathBuf {
    dir.join(LEGACY_CLOSE_PREF_FILE)
}

// ---- 读写 ----

/// 读磁盘上的原始 JSON 对象（坏 JSON / 不存在 → 空对象；未知键原样保留）。
fn load_raw_object(path: &Path) -> serde_json::Map<String, serde_json::Value> {
    match fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        },
        Err(_) => serde_json::Map::new(),
    }
}

/// 原子写（tmp + rename），失败静默降级为直接写（rename 跨设备等场景兜底）。
fn store_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text).map_err(|e| e.to_string())?;
    if fs::rename(&tmp, path).is_err() {
        fs::copy(&tmp, path).map_err(|e| e.to_string())?;
        let _ = fs::remove_file(&tmp);
    }
    Ok(())
}

/// 原始对象 → 类型化视图（缺键 None）。
fn typed_view(map: &serde_json::Map<String, serde_json::Value>) -> UiPreferences {
    serde_json::from_value(serde_json::Value::Object(map.clone())).unwrap_or_default()
}

/// 一次性导入旧 C++ 壳 `close-preference.json`（`{"action": "smart"|"tray"|"quit"}`）。
///
/// 仅当 `prefs` 文件尚不存在且 legacy 文件存在且 action 合法时种入；返回是否导入。
fn import_legacy_close_preference(
    dir: &Path,
    map: &mut serde_json::Map<String, serde_json::Value>,
) -> bool {
    if ui_prefs_path_for(dir).exists() {
        return false;
    }
    let Ok(text) = fs::read_to_string(legacy_close_pref_path_for(dir)) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let Some(action) = parsed.get("action").and_then(|v| v.as_str()) else {
        return false;
    };
    if !CLOSE_PREFERENCE_VALUES.contains(&action) {
        return false;
    }
    map.insert(
        "close_preference".to_string(),
        serde_json::Value::String(action.to_string()),
    );
    true
}

/// 加载有效偏好（含 legacy 导入副作用：导入后立即落盘一次）。
fn load_effective(dir: &Path) -> UiPreferences {
    let prefs_path = ui_prefs_path_for(dir);
    let mut map = load_raw_object(&prefs_path);
    if import_legacy_close_preference(dir, &mut map) {
        let _ = store_atomic(&prefs_path, &serde_json::Value::Object(map.clone()));
    }
    typed_view(&map).effective()
}

/// 合并补丁并持久化（只写补丁涉及的键；未知键保留），返回有效值视图。
fn apply_patch_and_store(dir: &Path, patch: UiPreferences) -> Result<UiPreferences, String> {
    let prefs_path = ui_prefs_path_for(dir);
    let mut map = load_raw_object(&prefs_path);

    let patch_value = serde_json::to_value(&patch).map_err(|e| e.to_string())?;
    if let serde_json::Value::Object(patch_map) = patch_value {
        for (key, value) in patch_map {
            map.insert(key, value);
        }
    }

    let effective = typed_view(&map).effective();
    store_atomic(&prefs_path, &serde_json::Value::Object(map))?;
    Ok(effective)
}

// ---- Tauri 托管状态（setup 时按真实目录构造；测试直接构造注入目录）----

/// 进程内共享的偏好存储（持锁串行化读写，避免并发写交错）。
pub struct UiPrefsStore {
    dir: PathBuf,
    inner: Mutex<()>,
}

impl UiPrefsStore {
    /// 生产构造：产品状态目录不可解析时不建 store（Command 返回错误）。
    #[must_use]
    pub fn from_product_dir() -> Option<Self> {
        Some(Self { dir: ui_state_dir()?, inner: Mutex::new(()) })
    }

    /// 测试构造：注入目录。
    #[cfg(test)]
    #[must_use]
    pub fn for_dir(dir: PathBuf) -> Self {
        Self { dir, inner: Mutex::new(()) }
    }

    /// 读有效偏好。
    ///
    /// # Errors
    /// 内部锁中毒（理论不可达：锁内无 panic 点）。
    pub fn get(&self) -> Result<UiPreferences, String> {
        let _guard = self.inner.lock().map_err(|e| e.to_string())?;
        Ok(load_effective(&self.dir))
    }

    /// 合并补丁、持久化并返回有效偏好。
    ///
    /// # Errors
    /// 持久化 IO 失败或内部锁中毒。
    pub fn set(&self, patch: UiPreferences) -> Result<UiPreferences, String> {
        let _guard = self.inner.lock().map_err(|e| e.to_string())?;
        apply_patch_and_store(&self.dir, patch)
    }
}

// ---- Commands ----

/// `ui_prefs_get`：读前端自有设置（有效值视图）。
#[tauri::command]
pub fn ui_prefs_get(store: State<'_, UiPrefsStore>) -> Result<UiPreferences, String> {
    store.get()
}

/// `ui_prefs_set`：合并补丁保存前端自有设置（不走 core config）。
#[tauri::command]
pub fn ui_prefs_set(
    store: State<'_, UiPrefsStore>,
    patch: UiPreferences,
) -> Result<UiPreferences, String> {
    store.set(patch)
}

// ---- 测试 ----

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "exv-ui-prefs-test-{}-{tag}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn read_json(dir: &Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(ui_prefs_path_for(dir)).expect("prefs file"))
            .expect("valid json")
    }

    #[test]
    fn roundtrip_preserves_set_fields_and_defaults_rest() {
        let dir = temp_dir("roundtrip");
        let store = UiPrefsStore::for_dir(dir.clone());

        let first = store.get().expect("get");
        assert_eq!(first.close_preference.as_deref(), Some("smart"));
        assert_eq!(first.minimize_to_tray_on_connect, Some(false));

        store
            .set(UiPreferences {
                minimize_to_tray_on_connect: Some(true),
                ..Default::default()
            })
            .expect("set");

        let json = read_json(&dir);
        assert_eq!(json["minimize_to_tray_on_connect"], serde_json::json!(true));
        // 未设置的键不落盘（skip_serializing_if），读回仍得默认值。
        assert!(json.get("launch_at_login").is_none());
        let second = store.get().expect("get");
        assert_eq!(second.minimize_to_tray_on_connect, Some(true));
        assert_eq!(second.silent_startup, Some(false));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_json_falls_back_to_defaults_without_crash() {
        let dir = temp_dir("corrupt");
        fs::write(ui_prefs_path_for(&dir), "{not valid json").expect("write junk");

        let store = UiPrefsStore::for_dir(dir.clone());
        let prefs = store.get().expect("get");
        assert_eq!(prefs.close_preference.as_deref(), Some("smart"));
        assert_eq!(prefs.minimize_to_tray_on_connect, Some(false));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_close_preference_value_falls_back_to_smart() {
        let dir = temp_dir("bad-close");
        fs::write(
            ui_prefs_path_for(&dir),
            r#"{"close_preference": "minimize"}"#,
        )
        .expect("write");

        let prefs = UiPrefsStore::for_dir(dir).get().expect("get");
        assert_eq!(prefs.close_preference.as_deref(), Some("smart"));
    }

    #[test]
    fn unknown_keys_are_preserved_on_disk_across_patches() {
        let dir = temp_dir("unknown-keys");
        fs::write(
            ui_prefs_path_for(&dir),
            r#"{"future_field": {"a": 1}, "silent_startup": true}"#,
        )
        .expect("write");

        let store = UiPrefsStore::for_dir(dir.clone());
        let prefs = store.get().expect("get");
        assert_eq!(prefs.silent_startup, Some(true));

        // 补丁只改自己的键；磁盘上的未知键保留（向前兼容：新版本写入的字段不被旧版本抹掉）。
        store
            .set(UiPreferences {
                launch_at_login: Some(true),
                ..Default::default()
            })
            .expect("set");
        let json = read_json(&dir);
        assert_eq!(json["future_field"], serde_json::json!({"a": 1}));
        assert_eq!(json["launch_at_login"], serde_json::json!(true));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn imports_legacy_close_preference_once() {
        let dir = temp_dir("legacy-import");
        fs::write(
            legacy_close_pref_path_for(&dir),
            r#"{"action": "quit"}"#,
        )
        .expect("write legacy");

        let store = UiPrefsStore::for_dir(dir.clone());
        let imported = store.get().expect("get");
        assert_eq!(imported.close_preference.as_deref(), Some("quit"));
        // 导入已落盘。
        assert_eq!(read_json(&dir)["close_preference"], serde_json::json!("quit"));

        // 之后改掉 close_preference 不再被 legacy 文件覆盖（幂等：仅目标文件不存在才导入）。
        store
            .set(UiPreferences {
                close_preference: Some("tray".into()),
                ..Default::default()
            })
            .expect("set");
        let again = store.get().expect("get");
        assert_eq!(again.close_preference.as_deref(), Some("tray"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_import_when_target_already_exists() {
        let dir = temp_dir("no-import");
        fs::write(ui_prefs_path_for(&dir), r#"{"close_preference": "tray"}"#)
            .expect("write prefs");
        fs::write(
            legacy_close_pref_path_for(&dir),
            r#"{"action": "quit"}"#,
        )
        .expect("write legacy");

        let prefs = UiPrefsStore::for_dir(dir).get().expect("get");
        assert_eq!(prefs.close_preference.as_deref(), Some("tray"));
    }

    #[test]
    fn patch_merges_without_clearing_unset_fields() {
        let dir = temp_dir("patch-merge");
        let store = UiPrefsStore::for_dir(dir.clone());
        store
            .set(UiPreferences {
                silent_startup: Some(true),
                connection_state_notifications: Some(true),
                ..Default::default()
            })
            .expect("seed");
        store
            .set(UiPreferences {
                silent_startup: Some(false),
                ..Default::default()
            })
            .expect("patch");

        let prefs = store.get().expect("get");
        assert_eq!(prefs.silent_startup, Some(false));
        assert_eq!(prefs.connection_state_notifications, Some(true));

        let _ = fs::remove_dir_all(&dir);
    }
}
