//! Windows 原生窗口壳。
//!
//! 网页只负责绘制标题栏的视觉外观；本模块负责 Windows 命中测试、模式尺寸
//! 和系统窗口动作。纯几何部分不依赖真实 HWND，便于在 Windows CI 外复核边界。

use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Emitter, LogicalSize, Runtime, State, WebviewWindow};

const TITLEBAR_LOGICAL_PX: i32 = 34;
const ADVANCED_SYSTEM_LOGICAL_PX: i32 = 132;
const MINIMAL_SYSTEM_LOGICAL_PX: i32 = 88;
// 完整模式右侧主题三位开关与窗口模式两位开关合计约 280px；保留少量
// 间距余量，避免 DPI 缩放或字体回退时把网页控件误判成拖动区。
const WEB_CONTROL_LOGICAL_PX: i32 = 288;
const ADVANCED_MIN_WIDTH: f64 = 860.0;
const ADVANCED_MIN_HEIGHT: f64 = 600.0;
const ADVANCED_DEFAULT_WIDTH: f64 = 1180.0;
const ADVANCED_DEFAULT_HEIGHT: f64 = 760.0;
const MINIMAL_WIDTH: f64 = 328.0;
const MINIMAL_HEIGHT: f64 = 136.0;

const SUBCLASS_ID: usize = 0x4558_565f_4348_524d;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowMode {
    Advanced,
    Minimal,
}

impl WindowMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "advanced" => Ok(Self::Advanced),
            "minimal" => Ok(Self::Minimal),
            other => Err(format!("不支持的窗口模式：{other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HitResult {
    Client,
    Caption,
    Minimize,
    Maximize,
    Close,
    ResizeLeft,
    ResizeRight,
    ResizeTop,
    ResizeBottom,
    ResizeTopLeft,
    ResizeTopRight,
    ResizeBottomLeft,
    ResizeBottomRight,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NativeWindowControl {
    Minimize,
    Maximize,
    Close,
}

impl NativeWindowControl {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "minimize" => Ok(Self::Minimize),
            "maximize" => Ok(Self::Maximize),
            "close" => Ok(Self::Close),
            other => Err(format!("不支持的窗口操作：{other}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativeWindowControlState {
    pub control: Option<NativeWindowControl>,
    pub pressed: bool,
}

fn native_window_control(result: HitResult) -> Option<NativeWindowControl> {
    match result {
        HitResult::Minimize => Some(NativeWindowControl::Minimize),
        HitResult::Maximize => Some(NativeWindowControl::Maximize),
        HitResult::Close => Some(NativeWindowControl::Close),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameMetrics {
    pub width_px: i32,
    pub height_px: i32,
    pub titlebar_px: i32,
    pub system_zone_px: i32,
    pub web_control_px: i32,
    pub resize_border_px: i32,
    pub mode: WindowMode,
}

impl FrameMetrics {
    pub fn from_logical(width: i32, height: i32, dpi: u32, mode: WindowMode) -> Self {
        let scale = (dpi.max(96) as f64) / 96.0;
        let px = |logical: i32| (logical as f64 * scale).round() as i32;
        Self {
            width_px: px(width),
            height_px: px(height),
            titlebar_px: px(TITLEBAR_LOGICAL_PX),
            system_zone_px: px(match mode {
                WindowMode::Advanced => ADVANCED_SYSTEM_LOGICAL_PX,
                WindowMode::Minimal => MINIMAL_SYSTEM_LOGICAL_PX,
            }),
            web_control_px: px(WEB_CONTROL_LOGICAL_PX),
            resize_border_px: px(8),
            mode,
        }
    }

    #[cfg(windows)]
    fn from_physical(width_px: i32, height_px: i32, dpi: u32, mode: WindowMode) -> Self {
        let scale = (dpi.max(96) as f64) / 96.0;
        let px = |logical: i32| (logical as f64 * scale).round() as i32;
        Self {
            width_px,
            height_px,
            titlebar_px: px(TITLEBAR_LOGICAL_PX),
            system_zone_px: px(match mode {
                WindowMode::Advanced => ADVANCED_SYSTEM_LOGICAL_PX,
                WindowMode::Minimal => MINIMAL_SYSTEM_LOGICAL_PX,
            }),
            web_control_px: px(WEB_CONTROL_LOGICAL_PX),
            resize_border_px: px(8),
            mode,
        }
    }

    fn is_minimal(self) -> bool {
        self.mode == WindowMode::Minimal
    }
}

pub fn hit_test(point: Point, frame: FrameMetrics) -> HitResult {
    if !frame.is_minimal() {
        let border = frame.resize_border_px;
        let left = point.x < border;
        let right = point.x >= frame.width_px - border;
        let top = point.y < border;
        let bottom = point.y >= frame.height_px - border;
        match (left, right, top, bottom) {
            (true, false, true, false) => return HitResult::ResizeTopLeft,
            (false, true, true, false) => return HitResult::ResizeTopRight,
            (true, false, false, true) => return HitResult::ResizeBottomLeft,
            (false, true, false, true) => return HitResult::ResizeBottomRight,
            (true, false, false, false) => return HitResult::ResizeLeft,
            (false, true, false, false) => return HitResult::ResizeRight,
            (false, false, true, false) => return HitResult::ResizeTop,
            (false, false, false, true) => return HitResult::ResizeBottom,
            _ => {}
        }
    }

    if point.y >= frame.titlebar_px {
        return HitResult::Client;
    }

    let system_start = frame.width_px - frame.system_zone_px;
    if point.x >= system_start {
        let local_x = point.x - system_start;
        if frame.is_minimal() {
            // 极简模式左半仍是网页外观/模式区，右半交给两个原生按钮。
            if local_x < frame.system_zone_px / 2 {
                return HitResult::Client;
            }
            let button_width = (frame.system_zone_px / 2).max(1) / 2;
            return if local_x < frame.system_zone_px / 2 + button_width {
                HitResult::Minimize
            } else {
                HitResult::Close
            };
        }
        let button_width = (frame.system_zone_px / 3).max(1);
        return if local_x < button_width {
            HitResult::Minimize
        } else if local_x < button_width * 2 {
            HitResult::Maximize
        } else {
            HitResult::Close
        };
    }

    if !frame.is_minimal() && point.x >= system_start - frame.web_control_px {
        HitResult::Client
    } else {
        HitResult::Caption
    }
}

struct ChromeData {
    mode: Mutex<WindowMode>,
    advanced_size: Mutex<LogicalSize<f64>>,
    advanced_was_maximized: Mutex<bool>,
    hovered_control: Mutex<Option<NativeWindowControl>>,
    pressed_control: Mutex<Option<NativeWindowControl>>,
    event_sink: Mutex<Option<Arc<dyn Fn(NativeWindowControlState) + Send + Sync>>>,
}

impl ChromeData {
    fn publish_control_state(&self) {
        let pressed_control = self
            .pressed_control
            .lock()
            .ok()
            .and_then(|pressed| *pressed);
        let control = pressed_control.or_else(|| {
            self.hovered_control
                .lock()
                .ok()
                .and_then(|hovered| *hovered)
        });
        let sink = self.event_sink.lock().ok().and_then(|sink| sink.clone());
        if let Some(sink) = sink {
            sink(NativeWindowControlState {
                control,
                pressed: pressed_control.is_some(),
            });
        }
    }

    fn set_event_sink(&self, sink: Arc<dyn Fn(NativeWindowControlState) + Send + Sync>) {
        if let Ok(mut current) = self.event_sink.lock() {
            *current = Some(sink);
        }
    }

    fn set_hovered_control(&self, control: Option<NativeWindowControl>) {
        let changed = self
            .hovered_control
            .lock()
            .map(|mut hovered| {
                if *hovered == control {
                    false
                } else {
                    *hovered = control;
                    true
                }
            })
            .unwrap_or(false);
        if changed {
            self.publish_control_state();
        }
    }

    fn set_pressed_control(&self, control: Option<NativeWindowControl>) {
        let changed = self
            .pressed_control
            .lock()
            .map(|mut pressed| {
                if *pressed == control {
                    false
                } else {
                    *pressed = control;
                    true
                }
            })
            .unwrap_or(false);
        if changed {
            self.publish_control_state();
        }
    }

    fn reset_control_state(&self) {
        let hovered_changed = self
            .hovered_control
            .lock()
            .map(|mut hovered| {
                let changed = hovered.is_some();
                *hovered = None;
                changed
            })
            .unwrap_or(false);
        let pressed_changed = self
            .pressed_control
            .lock()
            .map(|mut pressed| {
                let changed = pressed.is_some();
                *pressed = None;
                changed
            })
            .unwrap_or(false);
        if hovered_changed || pressed_changed {
            self.publish_control_state();
        }
    }
}

pub struct WindowChromeState {
    inner: Arc<ChromeData>,
}

impl WindowChromeState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ChromeData {
                mode: Mutex::new(WindowMode::Advanced),
                advanced_size: Mutex::new(LogicalSize::new(
                    ADVANCED_DEFAULT_WIDTH,
                    ADVANCED_DEFAULT_HEIGHT,
                )),
                advanced_was_maximized: Mutex::new(false),
                hovered_control: Mutex::new(None),
                pressed_control: Mutex::new(None),
                event_sink: Mutex::new(None),
            }),
        }
    }

    fn apply_mode<R: Runtime>(
        &self,
        window: &WebviewWindow<R>,
        requested: WindowMode,
    ) -> Result<(), String> {
        let current = *self.inner.mode.lock().map_err(|_| "窗口状态锁已损坏")?;
        if current == requested {
            return Ok(());
        }

        match (current, requested) {
            (WindowMode::Advanced, WindowMode::Minimal) => {
                let factor = window
                    .scale_factor()
                    .map_err(|error| format!("读取窗口缩放比例失败：{error}"))?;
                let physical = window
                    .inner_size()
                    .map_err(|error| format!("读取窗口尺寸失败：{error}"))?;
                *self
                    .inner
                    .advanced_size
                    .lock()
                    .map_err(|_| "窗口尺寸锁已损坏")? = LogicalSize::new(
                    f64::from(physical.width) / factor,
                    f64::from(physical.height) / factor,
                );
                *self
                    .inner
                    .advanced_was_maximized
                    .lock()
                    .map_err(|_| "窗口最大化状态锁已损坏")? = window
                    .is_maximized()
                    .map_err(|error| format!("读取窗口最大化状态失败：{error}"))?;
                if *self
                    .inner
                    .advanced_was_maximized
                    .lock()
                    .map_err(|_| "窗口最大化状态锁已损坏")?
                {
                    window
                        .unmaximize()
                        .map_err(|error| format!("退出最大化失败：{error}"))?;
                }
                window
                    .set_decorations(false)
                    .map_err(|error| format!("关闭系统装饰失败：{error}"))?;
                window
                    .set_resizable(false)
                    .map_err(|error| format!("锁定极简窗口尺寸失败：{error}"))?;
                let minimal = LogicalSize::new(MINIMAL_WIDTH, MINIMAL_HEIGHT);
                window
                    .set_min_size(Some(minimal))
                    .map_err(|error| format!("设置极简最小尺寸失败：{error}"))?;
                window
                    .set_max_size(Some(minimal))
                    .map_err(|error| format!("设置极简最大尺寸失败：{error}"))?;
                window
                    .set_size(minimal)
                    .map_err(|error| format!("设置极简窗口尺寸失败：{error}"))?;
            }
            (WindowMode::Minimal, WindowMode::Advanced) => {
                window
                    .set_resizable(true)
                    .map_err(|error| format!("恢复完整窗口缩放失败：{error}"))?;
                window
                    .set_max_size::<LogicalSize<f64>>(None)
                    .map_err(|error| format!("移除完整窗口最大尺寸失败：{error}"))?;
                window
                    .set_min_size(Some(LogicalSize::new(
                        ADVANCED_MIN_WIDTH,
                        ADVANCED_MIN_HEIGHT,
                    )))
                    .map_err(|error| format!("恢复完整窗口最小尺寸失败：{error}"))?;
                let size = *self
                    .inner
                    .advanced_size
                    .lock()
                    .map_err(|_| "窗口尺寸锁已损坏")?;
                window
                    .set_size(size)
                    .map_err(|error| format!("恢复完整窗口尺寸失败：{error}"))?;
                window
                    .set_decorations(false)
                    .map_err(|error| format!("保持无边框窗口失败：{error}"))?;
                if *self
                    .inner
                    .advanced_was_maximized
                    .lock()
                    .map_err(|_| "窗口最大化状态锁已损坏")?
                {
                    window
                        .maximize()
                        .map_err(|error| format!("恢复窗口最大化失败：{error}"))?;
                }
            }
            _ => unreachable!("窗口模式只允许在完整和极简之间切换"),
        }

        self.inner.reset_control_state();
        *self.inner.mode.lock().map_err(|_| "窗口状态锁已损坏")? = requested;
        Ok(())
    }
}

#[tauri::command]
pub async fn window_chrome_set_mode<R: Runtime>(
    window: WebviewWindow<R>,
    state: State<'_, WindowChromeState>,
    mode: String,
) -> Result<(), String> {
    state.apply_mode(&window, WindowMode::parse(&mode)?)
}

/// 由网页绘制的按钮通过这里调用真实窗口动作。
///
/// 控件区在 `WM_NCHITTEST` 中按客户区交给 WebView，不能再依赖 WebView2
/// 对 `HTMINBUTTON`/`HTMAXBUTTON`/`HTCLOSE` 的非客户区转发；否则按钮可能只
/// 能显示而不能收到 click。关闭继续保持既有“隐藏到托盘”语义。
#[tauri::command]
pub async fn window_chrome_control<R: Runtime>(
    window: WebviewWindow<R>,
    control: String,
) -> Result<(), String> {
    match NativeWindowControl::parse(&control)? {
        NativeWindowControl::Minimize => window
            .minimize()
            .map_err(|error| format!("窗口最小化失败：{error}")),
        NativeWindowControl::Maximize => {
            let maximized = window
                .is_maximized()
                .map_err(|error| format!("读取窗口最大化状态失败：{error}"))?;
            if maximized {
                window
                    .unmaximize()
                    .map_err(|error| format!("窗口还原失败：{error}"))
            } else {
                window
                    .maximize()
                    .map_err(|error| format!("窗口最大化失败：{error}"))
            }
        }
        NativeWindowControl::Close => window
            .hide()
            .map_err(|error| format!("窗口隐藏失败：{error}")),
    }
}

/// 窗口显隐（前端生命周期效果通道：连接后最小化到托盘 / 静默启动后托盘唤出）。
///
/// 与 `window_chrome_control(Close)` 的区别：这是纯显隐原语，不携带关闭语义——
/// close_preference 的决策在调用方（Rust setup/lifecycle）完成，前端只表达目标状态。
#[tauri::command]
pub async fn window_set_visible<R: Runtime>(
    window: WebviewWindow<R>,
    visible: bool,
) -> Result<(), String> {
    if visible {
        window
            .show()
            .map_err(|error| format!("窗口显示失败：{error}"))?;
        window
            .set_focus()
            .map_err(|error| format!("窗口聚焦失败：{error}"))
    } else {
        window
            .hide()
            .map_err(|error| format!("窗口隐藏失败：{error}"))
    }
}

#[cfg(not(windows))]
pub fn install<R: Runtime>(_app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::*;
    use tauri::Manager;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::UI::HiDpi::GetDpiForWindow;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        TME_LEAVE, TME_NONCLIENT, TRACKMOUSEEVENT, TrackMouseEvent,
    };
    use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowRect, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT, HTCAPTION, HTCLIENT, HTLEFT, HTRIGHT,
        HTTOP, HTTOPLEFT, HTTOPRIGHT, IsZoomed, PostMessageW,
        SC_MAXIMIZE, SC_MINIMIZE, SC_RESTORE, WM_CLOSE, WM_NCDESTROY, WM_NCHITTEST,
        WM_NCLBUTTONDOWN, WM_NCLBUTTONUP, WM_NCMOUSELEAVE, WM_NCMOUSEMOVE, WM_SYSCOMMAND,
    };

    fn point_from_lparam(lparam: LPARAM) -> Point {
        let packed = lparam.0 as u32;
        Point {
            x: i32::from(i16::from_ne_bytes((packed as u16).to_ne_bytes())),
            y: i32::from(i16::from_ne_bytes(((packed >> 16) as u16).to_ne_bytes())),
        }
    }

    fn hit_result_to_lresult(result: HitResult) -> LRESULT {
        let value = match result {
            HitResult::Client => HTCLIENT,
            HitResult::Caption => HTCAPTION,
            // 这些控件由 WebView 中的真实 button 接收 click；Rust command
            // 再执行窗口动作。返回客户区避免依赖 WebView2 对非客户区按钮
            // 消息的转发行为。
            HitResult::Minimize | HitResult::Maximize | HitResult::Close => HTCLIENT,
            HitResult::ResizeLeft => HTLEFT,
            HitResult::ResizeRight => HTRIGHT,
            HitResult::ResizeTop => HTTOP,
            HitResult::ResizeBottom => HTBOTTOM,
            HitResult::ResizeTopLeft => HTTOPLEFT,
            HitResult::ResizeTopRight => HTTOPRIGHT,
            HitResult::ResizeBottomLeft => HTBOTTOMLEFT,
            HitResult::ResizeBottomRight => HTBOTTOMRIGHT,
        };
        LRESULT(value as isize)
    }

    fn current_frame(hwnd: HWND, data: &ChromeData) -> Option<FrameMetrics> {
        let mut rect = RECT::default();
        unsafe { GetWindowRect(hwnd, &mut rect).ok()? };
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        let mode = *data.mode.lock().ok()?;
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        Some(FrameMetrics::from_physical(width, height, dpi, mode))
    }

    fn classify_screen_point(hwnd: HWND, lparam: LPARAM, data: &ChromeData) -> HitResult {
        let screen = point_from_lparam(lparam);
        let mut rect = RECT::default();
        if unsafe { GetWindowRect(hwnd, &mut rect) }.is_err() {
            return HitResult::Client;
        }
        let Some(frame) = current_frame(hwnd, data) else {
            return HitResult::Client;
        };
        hit_test(
            Point {
                x: screen.x - rect.left,
                y: screen.y - rect.top,
            },
            frame,
        )
    }

    fn track_non_client_leave(hwnd: HWND) {
        let mut event = TRACKMOUSEEVENT {
            cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
            dwFlags: TME_LEAVE | TME_NONCLIENT,
            hwndTrack: hwnd,
            dwHoverTime: 0,
        };
        unsafe {
            let _ = TrackMouseEvent(&mut event);
        }
    }

    fn dispatch_native_caption_action(hwnd: HWND, result: HitResult) {
        let command = match result {
            HitResult::Minimize => Some(SC_MINIMIZE),
            HitResult::Maximize => Some(if unsafe { IsZoomed(hwnd).as_bool() } {
                SC_RESTORE
            } else {
                SC_MAXIMIZE
            }),
            HitResult::Close => None,
            _ => return,
        };
        if let Some(command) = command {
            unsafe {
                let _ = PostMessageW(
                    Some(hwnd),
                    WM_SYSCOMMAND,
                    WPARAM(command as usize),
                    LPARAM(0),
                );
            }
        } else {
            unsafe {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
    }

    unsafe extern "system" fn chrome_subclass_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
        subclass_id: usize,
        ref_data: usize,
    ) -> LRESULT {
        let data = unsafe { &*(ref_data as *const ChromeData) };
        match message {
            WM_NCHITTEST => {
                let result = classify_screen_point(hwnd, lparam, data);
                data.set_hovered_control(native_window_control(result));
                return hit_result_to_lresult(result);
            }
            WM_NCMOUSEMOVE => {
                track_non_client_leave(hwnd);
                let result = classify_screen_point(hwnd, lparam, data);
                data.set_hovered_control(native_window_control(result));
            }
            WM_NCLBUTTONDOWN => {
                let result = classify_screen_point(hwnd, lparam, data);
                data.set_hovered_control(native_window_control(result));
                data.set_pressed_control(native_window_control(result));
            }
            WM_NCLBUTTONUP => {
                let result = classify_screen_point(hwnd, lparam, data);
                data.set_hovered_control(native_window_control(result));
                data.set_pressed_control(None);
                dispatch_native_caption_action(hwnd, result);
                return LRESULT(0);
            }
            WM_NCMOUSELEAVE => data.reset_control_state(),
            WM_NCDESTROY => unsafe {
                data.reset_control_state();
                let _ = RemoveWindowSubclass(hwnd, Some(chrome_subclass_proc), subclass_id);
                drop(Arc::from_raw(ref_data as *const ChromeData));
            },
            _ => {}
        }
        unsafe { DefSubclassProc(hwnd, message, wparam, lparam) }
    }

    pub fn install<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
        let Some(window) = app.get_webview_window("main") else {
            return Err(tauri::Error::WindowNotFound);
        };
        let tauri_hwnd = window.hwnd()?;
        // Tauri 当前通过其运行时依赖返回 windows 0.61 的 HWND；本应用的
        // windows API 依赖是 0.62，二者 ABI 相同但 Rust 类型不同，显式转接
        // 原始指针，避免把两个 crate 版本的句柄类型混用。
        let hwnd = HWND(tauri_hwnd.0);
        let state = app.state::<WindowChromeState>();
        let app_handle = app.clone();
        state.inner.set_event_sink(Arc::new(move |payload| {
            let _ = app_handle.emit("window-control-state", payload);
        }));
        let data = Arc::clone(&state.inner);
        let callback_data = Arc::into_raw(data) as usize;
        let installed = unsafe {
            SetWindowSubclass(
                hwnd,
                Some(chrome_subclass_proc as unsafe extern "system" fn(_, _, _, _, _, _) -> _),
                SUBCLASS_ID,
                callback_data,
            )
        };
        if installed.as_bool() {
            Ok(())
        } else {
            unsafe {
                drop(Arc::from_raw(callback_data as *const ChromeData));
            }
            Err(tauri::Error::Io(std::io::Error::other(
                "无法安装 Windows 原生窗口子类过程",
            )))
        }
    }
}

#[cfg(windows)]
pub fn install<R: Runtime>(app: &tauri::AppHandle<R>) -> tauri::Result<()> {
    native::install(app)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        FrameMetrics, HitResult, NativeWindowControl, NativeWindowControlState, Point,
        WindowChromeState, WindowMode, hit_test, native_window_control,
    };

    #[test]
    fn native_hit_results_map_to_distinct_controls() {
        assert_eq!(
            native_window_control(HitResult::Minimize),
            Some(NativeWindowControl::Minimize)
        );
        assert_eq!(
            native_window_control(HitResult::Maximize),
            Some(NativeWindowControl::Maximize)
        );
        assert_eq!(
            native_window_control(HitResult::Close),
            Some(NativeWindowControl::Close)
        );
        assert_eq!(native_window_control(HitResult::Caption), None);
    }

    #[test]
    fn native_control_state_publishes_hover_and_reset() {
        let state = WindowChromeState::new();
        let events: Arc<Mutex<Vec<NativeWindowControlState>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_events = Arc::clone(&events);
        state.inner.set_event_sink(Arc::new(move |payload| {
            sink_events.lock().expect("event lock").push(payload);
        }));

        state
            .inner
            .set_hovered_control(Some(NativeWindowControl::Close));
        state
            .inner
            .set_pressed_control(Some(NativeWindowControl::Close));
        state.inner.reset_control_state();

        let events = events.lock().expect("event lock");
        assert_eq!(
            events[0],
            NativeWindowControlState {
                control: Some(NativeWindowControl::Close),
                pressed: false,
            }
        );
        assert_eq!(
            events[1],
            NativeWindowControlState {
                control: Some(NativeWindowControl::Close),
                pressed: true,
            }
        );
        assert_eq!(
            events[2],
            NativeWindowControlState {
                control: None,
                pressed: false,
            }
        );
    }

    #[test]
    fn advanced_titlebar_preserves_web_controls_and_owns_native_buttons() {
        let frame = FrameMetrics::from_logical(1200, 760, 96, WindowMode::Advanced);
        assert_eq!(hit_test(Point { x: 420, y: 16 }, frame), HitResult::Caption);
        assert_eq!(hit_test(Point { x: 820, y: 16 }, frame), HitResult::Client);
        assert_eq!(hit_test(Point { x: 1000, y: 16 }, frame), HitResult::Client);
        assert_eq!(
            hit_test(Point { x: 1090, y: 16 }, frame),
            HitResult::Minimize
        );
        assert_eq!(
            hit_test(Point { x: 1134, y: 16 }, frame),
            HitResult::Maximize
        );
        assert_eq!(hit_test(Point { x: 1178, y: 16 }, frame), HitResult::Close);
    }

    #[test]
    fn minimal_titlebar_has_no_maximize_button_and_no_resize_border() {
        let frame = FrameMetrics::from_logical(328, 136, 96, WindowMode::Minimal);
        assert_eq!(hit_test(Point { x: 220, y: 16 }, frame), HitResult::Caption);
        assert_eq!(hit_test(Point { x: 260, y: 16 }, frame), HitResult::Client);
        assert_eq!(
            hit_test(Point { x: 284, y: 16 }, frame),
            HitResult::Minimize
        );
        assert_eq!(hit_test(Point { x: 326, y: 16 }, frame), HitResult::Close);
        assert_ne!(
            hit_test(Point { x: 0, y: 68 }, frame),
            HitResult::ResizeLeft
        );
    }

    #[test]
    fn advanced_window_keeps_dpi_scaled_eight_logical_pixel_resize_border() {
        let frame = FrameMetrics::from_logical(1200, 760, 144, WindowMode::Advanced);
        assert_eq!(frame.resize_border_px, 12);
        assert_eq!(
            hit_test(Point { x: 2, y: 400 }, frame),
            HitResult::ResizeLeft
        );
    }
}
