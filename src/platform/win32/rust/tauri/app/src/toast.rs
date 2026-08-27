//! 系统 toast 通知（Windows 10/11 通知弹窗，进通知中心）。
//!
//! 用 WinRT `ToastNotificationManager` + 本应用自注册 AUMID（= tauri.conf.json 的
//! `identifier`，见 [`crate::toast_identity`]）。AUMID 需在系统「注册」才能显示 EXV 名字：
//! 注册由 [`crate::toast_identity::ensure_toast_identity_registered`] 在启动时幂等完成
//! （Start menu 快捷方式 + `System.AppUserModelID` 属性）。旧实现复用 PowerShell 的 AUMID，
//! toast 名头因此显示「Windows PowerShell」；R8 起改为 EXV 身份。
//!
//! 图标增强：toast 绑定 appLogoOverride = 状态目录里缓存的 EXV 图标（可选，图标不可用时
//! toast 仍以文本正常显示）。失败返回 false，调用方回退托盘气泡。

use windows::core::HSTRING;
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

/// XML 文本转义（toast payload 是 XML 字符串拼接，标题/正文/URI 需转义）。
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// 组装 ToastGeneric XML。`icon_uri` 非空时追加 appLogoOverride（EXV 图标）。
fn toast_xml(title: &str, body: &str, icon_uri: Option<&str>) -> String {
    let icon = icon_uri
        .filter(|uri| !uri.is_empty())
        .map(|uri| format!("<image placement=\"appLogoOverride\" src=\"{}\"/>", escape_xml(uri)))
        .unwrap_or_default();
    format!(
        "<toast><visual><binding template=\"ToastGeneric\">{icon}<text>{}</text><text>{}</text></binding></visual></toast>",
        escape_xml(title),
        escape_xml(body),
    )
}

/// 弹一条系统 toast。成功 true；任何一步失败 false（调用方回退气泡）。
pub fn show_toast(title: &str, body: &str) -> bool {
    let icon_uri = crate::toast_identity::toast_icon_uri();
    let xml = toast_xml(title, body, icon_uri.as_deref());

    let xml_doc = match XmlDocument::new() {
        Ok(doc) => doc,
        Err(_) => return false,
    };
    if xml_doc.LoadXml(&HSTRING::from(xml)).is_err() {
        return false;
    }

    let toast = match ToastNotification::CreateToastNotification(&xml_doc) {
        Ok(t) => t,
        Err(_) => return false,
    };

    let notifier =
        match ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
            crate::toast_identity::AUMID,
        )) {
            Ok(n) => n,
            Err(_) => return false,
        };
    // Show 是 fire-and-forget；横幅是否弹出由用户系统通知设置决定（通知中心始终可达）。
    notifier.Show(&toast).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_xml_handles_special_chars() {
        assert_eq!(escape_xml("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d&quot;e");
    }

    #[test]
    fn toast_xml_without_icon_has_no_image() {
        let xml = toast_xml("标题", "正文", None);
        assert!(!xml.contains("<image"));
        assert!(xml.contains("<text>标题</text>"));
        assert!(xml.contains("<text>正文</text>"));
        assert!(xml.contains("template=\"ToastGeneric\""));
    }

    #[test]
    fn toast_xml_with_icon_embeds_applogo_override() {
        let xml = toast_xml("标题", "正文", Some("file:///C:/EXV/toast-icon.png"));
        assert!(xml.contains(
            "<image placement=\"appLogoOverride\" src=\"file:///C:/EXV/toast-icon.png\"/>"
        ));
    }

    #[test]
    fn toast_xml_escapes_injected_tags_in_body() {
        let xml = toast_xml("t", "<script>alert(1)</script>", None);
        assert!(!xml.contains("<script>"));
        assert!(xml.contains("&lt;script&gt;"));
    }
}
