//! 自管托盘（Shell_NotifyIcon）+ 托盘气泡通知。
//!
//! 为什么不用 `tauri::tray`：气泡通知（NIF_INFO）需要自持 NOTIFYICONDATA 做
//! NIM_MODIFY，tauri tray API 不暴露原始图标数据；自管还保证全应用只有一个
//! 托盘图标（lifecycle.rs 不再注册 tauri tray）。
//!
//! 行为对齐 C++ 壳（`webview2_host_win32.cpp`）：
//!   * 左键单击 = 显示窗口；
//!   * 右键菜单 = 显示 EXV / 退出（退出走 O3 停机 [`crate::lifecycle::notify_core_shutdown`]）；
//!   * 气泡通知 = `show_tray_notification(title, body)` 同款 NIM_MODIFY + NIF_INFO。
//!
//! 窗口操作（显示主窗口）与退出动作经 [`set_show_handler`] / [`set_quit_handler`]
//| 注入（lib.rs setup 提供 tauri 侧实现），本模块只管 Win32 交互面。

use std::sync::OnceLock;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW,
    Shell_NotifyIconW,
};
use windows::Win32::Graphics::Gdi::{CreateBitmap, DeleteObject};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconIndirect, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon,
    DestroyMenu, DispatchMessageW, GetMessageW, GetCursorPos, HICON, ICONINFO, MF_SEPARATOR,
    MF_STRING, PostQuitMessage, RegisterClassW, SetForegroundWindow, TrackPopupMenu,
    TranslateMessage, MSG, TPM_BOTTOMALIGN, TPM_LEFTALIGN, WM_APP, WM_COMMAND, WM_DESTROY,
    WM_LBUTTONUP, WM_RBUTTONUP, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
};

/// 托盘回调消息基址（WM_APP 区段，不与框架消息冲突；对齐 C++ 壳 `WM_APP + 0x42` 惯例）。
const TRAY_CALLBACK_MSG: u32 = WM_APP + 0x51;
/// 右键菜单项 id。
const MENU_SHOW: usize = 2001;
const MENU_QUIT: usize = 2002;
/// 托盘图标 id（单实例固定 1）。
const TRAY_ID: u32 = 1;

/// HICON/HWND 是裸句柄（`*mut c_void`，非 Send/Sync）；托盘状态只在安装线程写入、
/// 消息泵线程读取其 HWND 字段做 Shell 调用——Windows 句柄跨线程使用是合法的，
/// 这里用包装类型声明该契约。
#[derive(Clone, Copy)]
struct TrayHandles(*mut core::ffi::c_void);
unsafe impl Send for TrayHandles {}
unsafe impl Sync for TrayHandles {}

struct TrayState {
    /// 托盘消息窗口句柄（气泡修改需要）。
    hwnd: TrayHandles,
    /// 托盘图标句柄（退出时释放）。
    icon: TrayHandles,
}

static TRAY: OnceLock<TrayState> = OnceLock::new();
static ON_QUIT: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();
static ON_SHOW: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// 注册「退出」回调（O3 停机入口；setup 阶段调用一次）。
pub fn set_quit_handler(handler: impl Fn() + Send + Sync + 'static) {
    let _ = ON_QUIT.set(Box::new(handler));
}

/// 注册「显示主窗口」回调（lib.rs setup 注入 tauri window.show + set_focus）。
pub fn set_show_handler(handler: impl Fn() + Send + Sync + 'static) {
    let _ = ON_SHOW.set(Box::new(handler));
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 把 source 截断写入定长 UTF-16 缓冲并保证 NUL 结尾。
fn fill_utf16_buf(buf: &mut [u16], source: &str) {
    let mut written = 0usize;
    for ch in source.chars() {
        let mut encoded = [0u16; 2];
        for unit in ch.encode_utf16(&mut encoded) {
            if written >= buf.len() - 1 {
                break;
            }
            buf[written] = *unit;
            written += 1;
        }
    }
    // 清零剩余部分（NUL 结尾由清零保证）。
    for slot in &mut buf[written..] {
        *slot = 0;
    }
}

extern "system" fn tray_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        if msg == TRAY_CALLBACK_MSG {
            let mouse = (lparam.0 & 0xFFFF) as u32;
            if mouse == WM_RBUTTONUP {
                show_context_menu(hwnd);
            } else if mouse == WM_LBUTTONUP {
                invoke_show();
            }
            return LRESULT(0);
        }
        if msg == WM_COMMAND {
            match (wparam.0 & 0xFFFF) as usize {
                id if id == MENU_SHOW => invoke_show(),
                id if id == MENU_QUIT => {
                    if let Some(quit) = ON_QUIT.get() {
                        quit();
                    }
                }
                _ => {}
            }
            return LRESULT(0);
        }
        if msg == WM_DESTROY {
            PostQuitMessage(0);
            return LRESULT(0);
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }
}

fn show_context_menu(hwnd: HWND) {
    unsafe {
        let Ok(menu) = CreatePopupMenu() else { return };
        let _ = AppendMenuW(menu, MF_STRING, MENU_SHOW, w!("显示 EXV"));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, None);
        let _ = AppendMenuW(menu, MF_STRING, MENU_QUIT, w!("退出"));
        let mut cursor = POINT::default();
        let _ = GetCursorPos(&mut cursor);
        // TrackPopupMenu 需要前台窗口才能正确收到菜单关闭消息。
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenu(
            menu,
            TPM_LEFTALIGN | TPM_BOTTOMALIGN,
            cursor.x,
            cursor.y,
            None,
            hwnd,
            None,
        );
        let _ = DestroyMenu(menu);
    }
}

fn invoke_show() {
    if let Some(show) = ON_SHOW.get() {
        show();
    }
}

/// 托盘图标渲染（纯像素处理，可单测）：先按 alpha 裁掉全透明边，再按 alpha
/// 预乘做面积平均（area-average）缩放到 32×32，最后翻转为 bottom-up BGRA
/// （`CreateBitmap` 32bpp 期望的格式）。
///
/// 为什么这样做：
///   * **trim**：把内容区域（alpha bbox）最大化贴满目标画布，透明边不再以
///     白边/透明边形式残留——浅色任务栏上白盾牌不会再「白对白」糊成一团；
///   * **面积平均 + alpha 预乘**：256²→32² 是 8:1 大倍数缩小。面积平均等价于
///     高质量超采样，边缘像素按实际覆盖面积加权，抗锯齿自然保留；旧实现用
///     最近邻稀疏采样，会丢抗锯齿、白色细线（网络线/盾牌描边）断裂成噪点。
///     预乘避免半透明边缘出现黑/白描边（halo）。
///
/// 返回 None 表示源为空或全透明。
fn render_tray_bgra(rgba: &[u8], width: usize, height: usize) -> Option<Vec<u8>> {
    const SIZE: usize = 32;
    if width == 0 || height == 0 || rgba.len() < width * height * 4 {
        return None;
    }

    // 1) 全透明边 bbox（alpha > 0 即视为内容）。
    let (mut x0, mut y0, mut x1, mut y1) = (width, height, 0usize, 0usize);
    for y in 0..height {
        let row = y * width * 4;
        for x in 0..width {
            if rgba[row + x * 4 + 3] != 0 {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x);
                y1 = y1.max(y);
            }
        }
    }
    if x1 < x0 || y1 < y0 {
        return None; // 全透明
    }
    let (cw, ch) = (x1 - x0 + 1, y1 - y0 + 1);

    // 2) 面积平均缩放到 32×32（内容拉伸填满，不留白边）。
    let mut top_down = vec![0u8; SIZE * SIZE * 4];
    for dy in 0..SIZE {
        let fy0 = dy as f64 * ch as f64 / SIZE as f64;
        let fy1 = (dy as f64 + 1.0) * ch as f64 / SIZE as f64;
        for dx in 0..SIZE {
            let fx0 = dx as f64 * cw as f64 / SIZE as f64;
            let fx1 = (dx as f64 + 1.0) * cw as f64 / SIZE as f64;
            let sx0 = fx0.floor() as usize;
            let sx1 = (fx1.ceil() as usize).min(cw);
            let sy0 = fy0.floor() as usize;
            let sy1 = (fy1.ceil() as usize).min(ch);
            let (mut pr, mut pg, mut pb, mut pa, mut area) =
                (0.0f64, 0.0f64, 0.0f64, 0.0f64, 0.0f64);
            for sy in sy0..sy1 {
                let wy = ((sy as f64 + 1.0).min(fy1) - (sy as f64).max(fy0)).max(0.0);
                for sx in sx0..sx1 {
                    let wx = ((sx as f64 + 1.0).min(fx1) - (sx as f64).max(fx0)).max(0.0);
                    let w = wx * wy;
                    let i = (y0 + sy) * width * 4 + (x0 + sx) * 4;
                    let a = rgba[i + 3] as f64 / 255.0;
                    pr += rgba[i] as f64 * a * w;
                    pg += rgba[i + 1] as f64 * a * w;
                    pb += rgba[i + 2] as f64 * a * w;
                    pa += a * w;
                    area += w;
                }
            }
            let di = (dy * SIZE + dx) * 4;
            if pa > 0.0 && area > 0.0 {
                let alpha = pa / area;
                top_down[di + 3] = (alpha * 255.0).round() as u8;
                top_down[di] = (pr / pa).round() as u8;
                top_down[di + 1] = (pg / pa).round() as u8;
                top_down[di + 2] = (pb / pa).round() as u8;
            }
        }
    }

    // 3) `CreateBitmap` 按传入的 top-down 扫描线解释颜色位图；只转换
    // RGBA→BGRA，绝不能额外翻转行序，否则托盘图标会垂直镜像。
    let mut bgra = vec![0u8; SIZE * SIZE * 4];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let si = (y * SIZE + x) * 4;
            let di = (y * SIZE + x) * 4;
            bgra[di] = top_down[si + 2];
            bgra[di + 1] = top_down[si + 1];
            bgra[di + 2] = top_down[si];
            bgra[di + 3] = top_down[si + 3];
        }
    }
    Some(bgra)
}

/// 返回一个全 0 的 1bpp AND 掩码。`CreateIconIndirect` 将该掩码按位解释为透明
/// 判据，因此绝不能把未初始化的 GDI bitmap 交给它：全 0 表示由 32bpp 色彩图（含
/// alpha）决定可见像素，避免 Shell 把整个图标当成透明。
fn opaque_and_mask(size: usize) -> Vec<u8> {
    let bytes_per_row = size.div_ceil(32) * 4;
    vec![0; bytes_per_row * size]
}

/// 把 RGBA 像素（tauri Image）转成 32×32 32bpp HICON（托盘图标）。
/// 像素处理见 [`render_tray_bgra`]（trim + 面积平均 + bottom-up BGRA）。
fn hicon_from_rgba(image: &tauri::image::Image<'_>) -> Option<HICON> {
    const SIZE: i32 = 32;
    let bgra = render_tray_bgra(image.rgba(), image.width() as usize, image.height() as usize)?;
    let and_mask_pixels = opaque_and_mask(SIZE as usize);

    unsafe {
        // `CreateBitmap(..., None)` 留下未初始化的 AND 掩码；Shell 会把其中的 1
        // 当透明像素，表现为偶发或全透明托盘图标。明确传全 0 让 32bpp 图标的 alpha
        // 成为唯一透明度来源。
        let and_mask = CreateBitmap(SIZE, SIZE, 1, 1, Some(and_mask_pixels.as_ptr().cast()));
        if and_mask.is_invalid() {
            return None;
        }
        let color = CreateBitmap(SIZE, SIZE, 1, 32, Some(bgra.as_ptr().cast()));
        if color.is_invalid() {
            let _ = DeleteObject(and_mask.into());
            return None;
        }
        let info = ICONINFO {
            fIcon: true.into(),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: and_mask,
            hbmColor: color,
        };
        let handle = CreateIconIndirect(&info);
        let _ = DeleteObject(and_mask.into());
        let _ = DeleteObject(color.into());
        match handle {
            Ok(h) if !h.is_invalid() => Some(h),
            _ => None,
        }
    }
}

/// 安装自管托盘。失败返回 Err（调用方记录并降级为无托盘，行为同旧 tauri tray 缺图标分支）。
///
/// # Errors
/// 窗口类注册 / 消息窗口创建 / 图标渲染 / NIM_ADD 失败，或托盘已安装。
pub fn install_tray() -> Result<(), String> {
    static CLASS_REGISTERED: OnceLock<()> = OnceLock::new();

    unsafe {
        let module = GetModuleHandleW(None).map_err(|e| e.to_string())?;

        let class_name = wide("EXV Tray Window");
        if CLASS_REGISTERED.get().is_none() {
            let wc = WNDCLASSW {
                lpfnWndProc: Some(tray_proc),
                hInstance: module.into(),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                return Err("RegisterClassW failed".into());
            }
            let _ = CLASS_REGISTERED.set(());
        }

        let window_name = wide("EXV Tray");
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(window_name.as_ptr()),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(module.into()),
            None,
        )
        .map_err(|e| format!("CreateWindowExW failed: {e}"))?;

        // 图标：显式用 app/icons/icon.png（256² 品牌红盾牌 logo）。不走
        // ExtractIconExW(exe, ...)——exe 内嵌 icon.ico 的默认帧在 16px 下会把
        // 白色盾牌糊成白块/白边（浅色任务栏白对白近不可见 = 「空/透明」），是
        // 托盘 icon 未就位的根因之一。这里先裁掉全透明边、再按 alpha 预乘面积
        // 平均缩放到 32×32（内容贴满、无白边、非最近邻），Windows 再下采样到
        // 托盘显示尺寸时像素质量不损。
        let embedded = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png"))
            .ok()
            .and_then(|img| hicon_from_rgba(&img));
        let icon = match embedded {
            Some(handle) => handle,
            None => {
                return Err(
                    "no icon available for tray (embedded icon.png decode/render failed)".into(),
                )
            }
        };

        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: TRAY_ID,
            uFlags: NIF_MESSAGE | NIF_ICON,
            uCallbackMessage: TRAY_CALLBACK_MSG,
            hIcon: icon,
            ..Default::default()
        };
        if !Shell_NotifyIconW(NIM_ADD, &mut nid).as_bool() {
            let _ = DestroyIcon(icon);
            return Err("Shell_NotifyIconW(NIM_ADD) failed".into());
        }

        if TRAY
            .set(TrayState {
                hwnd: TrayHandles(hwnd.0),
                icon: TrayHandles(icon.0),
            })
            .is_err()
        {
            return Err("tray already installed".into());
        }
    }

    // 消息泵线程：托盘交互事件在此分发；进程退出随线程终止（daemon 性质，不 join）。
    // HWND 跨线程传递经包装类型声明契约（见 TrayHandles 注释）。
    let pump_hwnd = TrayHandles(TRAY.get().map(|s| s.hwnd.0).unwrap_or(std::ptr::null_mut()));
    std::thread::Builder::new()
        .name("exv-tray".into())
        .spawn(move || unsafe {
            // 整体 move TrayHandles（Send 包装），块内再取裸句柄——
            // 直接写 `pump_hwnd.0` 会让闭包按字段精确捕获裸指针（非 Send）。
            let pump = pump_hwnd;
            let hwnd = HWND(pump.0);
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, Some(hwnd), 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        })
        .map_err(|e| format!("tray thread spawn failed: {e}"))?;

    Ok(())
}

/// 卸载托盘（移除图标并释放句柄；进程退出前调用）。
pub fn remove_tray() {
    if let Some(state) = TRAY.get() {
        let mut nid = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: HWND(state.hwnd.0),
            uID: TRAY_ID,
            ..Default::default()
        };
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &mut nid);
            let _ = DestroyIcon(HICON(state.icon.0));
        }
    }
}

/// 连接状态通知：优先系统 toast 弹窗（Windows 10/11 通知中心可见、有横幅），
/// 失败回退托盘气泡（NIF_INFO）。`tray_notify` Command 调用此函数。
pub fn notify(title: &str, body: &str) {
    if crate::toast::show_toast(title, body) {
        return;
    }
    tray_balloon(title, body);
}

/// 托盘气泡通知（NIM_MODIFY + NIF_INFO）。未安装托盘时静默丢弃。
fn tray_balloon(title: &str, body: &str) {
    let Some(state) = TRAY.get() else { return };
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: HWND(state.hwnd.0),
        uID: TRAY_ID,
        uFlags: NIF_INFO,
        ..Default::default()
    };
    fill_utf16_buf(&mut nid.szInfoTitle, title);
    fill_utf16_buf(&mut nid.szInfo, body);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &mut nid);
    }
}

/// `tray_notify` Command：前端触发的托盘气泡（通断通知通道）。
#[tauri::command]
pub fn tray_notify(title: String, body: String) {
    notify(&title, &body);
}

#[cfg(test)]
mod tests {
    use super::{hicon_from_rgba, opaque_and_mask, render_tray_bgra};
    use windows::Win32::Graphics::Gdi::{
        CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC, GetPixel,
        ReleaseDC, SelectObject,
    };
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, DrawIconEx, DI_NORMAL};

    /// 读取 top-down BGRA 缓冲里 (x, y)（y = 0 为显示顶行）的 B,G,R,A。
    fn px(buf: &[u8], x: usize, y: usize) -> (u8, u8, u8, u8) {
        let i = (y * 32 + x) * 4;
        (buf[i], buf[i + 1], buf[i + 2], buf[i + 3])
    }

    #[test]
    fn empty_source_returns_none() {
        assert!(render_tray_bgra(&[], 0, 0).is_none());
        assert!(render_tray_bgra(&[0u8; 16], 2, 2).is_none()); // 长度不足
    }

    #[test]
    fn fully_transparent_returns_none() {
        let rgba = vec![0u8; 8 * 8 * 4];
        assert!(render_tray_bgra(&rgba, 8, 8).is_none());
    }

    #[test]
    fn tray_and_mask_is_explicitly_opaque() {
        let mask = opaque_and_mask(32);
        assert_eq!(mask.len(), 128, "32px 1bpp mask uses 4 bytes per row");
        assert!(
            mask.iter().all(|byte| *byte == 0),
            "AND mask must be initialized to opaque pixels; uninitialized bits can make the entire tray icon transparent"
        );
    }

    #[test]
    fn trim_removes_margin_and_fills_canvas() {
        // 4×4：仅中心 2×2 白色不透明，四周全透明。
        let mut rgba = vec![0u8; 4 * 4 * 4];
        for y in 2..4 {
            for x in 2..4 {
                let i = (y * 4 + x) * 4;
                rgba[i..i + 3].copy_from_slice(&[255, 255, 255]);
                rgba[i + 3] = 255;
            }
        }
        let buf = render_tray_bgra(&rgba, 4, 4).expect("render");
        // 内容应贴满 32×32：全部像素不透明且为白色，无透明/白边残留。
        for y in 0..32 {
            for x in 0..32 {
                assert_eq!(px(&buf, x, y), (255, 255, 255, 255), "at ({x},{y})");
            }
        }
    }

    #[test]
    fn single_pixel_content_fills_entire_canvas() {
        // 4×4：仅左上角 1 个红色像素不透明。
        let mut rgba = vec![0u8; 4 * 4 * 4];
        rgba[0..4].copy_from_slice(&[255, 0, 0, 255]);
        let buf = render_tray_bgra(&rgba, 4, 4).expect("render");
        for y in 0..32 {
            for x in 0..32 {
                assert_eq!(px(&buf, x, y), (0, 0, 255, 255), "at ({x},{y})");
            }
        }
    }

    #[test]
    fn create_bitmap_keeps_top_down_scanline_order() {
        // 2×2：上行红、下行蓝（top-down）。传给 CreateBitmap 的行序必须保持
        // top-down；否则 Windows 托盘会把整个图标上下翻转。
        let rgba: [u8; 16] = [
            255, 0, 0, 255, 255, 0, 0, 255, // row0: red
            0, 0, 255, 255, 0, 0, 255, 255, // row1: blue
        ];
        let buf = render_tray_bgra(&rgba, 2, 2).expect("render");
        assert_eq!(px(&buf, 0, 0), (0, 0, 255, 255), "buffer row0 = 红");
        assert_eq!(px(&buf, 0, 15), (0, 0, 255, 255), "buffer row15 = 红");
        assert_eq!(px(&buf, 0, 16), (255, 0, 0, 255), "buffer row16 = 蓝");
        assert_eq!(px(&buf, 0, 31), (255, 0, 0, 255), "buffer row31 = 蓝");
    }

    #[test]
    fn windows_hicon_draws_top_source_row_at_the_visual_top() {
        // 直接走 CreateIconIndirect → DrawIconEx：上红下蓝的源图必须仍是视觉上红下蓝。
        // 这覆盖实际 Windows 图标绘制路径，防止今后又在扫描线方向上做重复翻转。
        let image = tauri::image::Image::new_owned(
            vec![
                255, 0, 0, 255, 255, 0, 0, 255, // top: red
                0, 0, 255, 255, 0, 0, 255, 255, // bottom: blue
            ],
            2,
            2,
        );
        let icon = hicon_from_rgba(&image).expect("create HICON");
        unsafe {
            let screen = GetDC(None);
            assert!(!screen.is_invalid(), "obtain screen DC");
            let memory = CreateCompatibleDC(Some(screen));
            assert!(!memory.is_invalid(), "create memory DC");
            let canvas = CreateCompatibleBitmap(screen, 32, 32);
            assert!(!canvas.is_invalid(), "create canvas bitmap");
            let previous = SelectObject(memory, canvas.into());

            DrawIconEx(memory, 0, 0, icon, 32, 32, 0, None, DI_NORMAL).expect("draw HICON");
            let top = GetPixel(memory, 0, 0).0;
            let bottom = GetPixel(memory, 0, 31).0;

            let _ = SelectObject(memory, previous);
            let _ = DeleteObject(canvas.into());
            let _ = DeleteDC(memory);
            let _ = ReleaseDC(None, screen);
            let _ = DestroyIcon(icon);

            assert_eq!(top & 0x0000_00FF, 0xFF, "visual top is red");
            assert_eq!(top & 0x00FF_0000, 0x00, "visual top is not blue");
            assert_eq!(bottom & 0x0000_00FF, 0x00, "visual bottom is not red");
            assert_eq!(bottom & 0x00FF_0000, 0xFF00_00, "visual bottom is blue");
        }
    }

    #[test]
    fn real_icon_fills_canvas_with_red_and_white() {
        let img = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png"))
            .expect("decode embedded icon.png");
        let buf =
            render_tray_bgra(img.rgba(), img.width() as usize, img.height() as usize)
                .expect("render");
        let mut opaque = 0u32;
        let (mut red, mut white) = (0u32, 0u32);
        let mut row_opaque = [0u32; 32];
        let mut col_opaque = [0u32; 32];
        for y in 0..32 {
            for x in 0..32 {
                let (b, g, r, a) = px(&buf, x, y);
                if a != 0 {
                    opaque += 1;
                    row_opaque[y] += 1;
                    col_opaque[x] += 1;
                    if r > 200 && g > 200 && b > 200 {
                        white += 1;
                    } else if r > 90 && r > g + 30 && r > b + 30 {
                        red += 1;
                    }
                }
            }
        }
        // 内容贴满：任一边界行/列都不全透明（无白边残留）。
        assert!(row_opaque[0] > 0 && row_opaque[31] > 0, "边界行不透明");
        assert!(col_opaque[0] > 0 && col_opaque[31] > 0, "边界列不透明");
        // 红盾牌与白内容都在，且非空、非纯白块（品牌红占主导，深/浅任务栏均可见）。
        assert!(red > 0 && white > 0, "红白内容都存在");
        assert!(opaque > 32 * 32 / 2, "内容覆盖超过一半画布");
    }
}
