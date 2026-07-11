#include "platform/win32/ui_shell/webview2_host_win32.hpp"

#include "app/ui_shell/close_preference.hpp"
#include "platform/win32/ui_shell/resource.hpp"
#include "platform/win32/ui_shell/webview2_runtime_win32.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <windowsx.h>

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(EXV_BUILD_UI_SHELL)
#include <WebView2.h>
#include <nlohmann/json.hpp>
#include <objbase.h>
#include <shellapi.h>
#endif

namespace exv::platform::win32::ui_shell {

namespace {

constexpr char kPackagedRendererHost[] = "appassets.exv.invalid";
constexpr wchar_t kPackagedRendererHostWide[] =
    L"appassets.exv.invalid";
constexpr DWORD kFixedWindowStyle =
    WS_OVERLAPPED | WS_SYSMENU | WS_MINIMIZEBOX;
constexpr int kTrayCommandShow = 1001;
constexpr int kTrayCommandQuit = 1002;
constexpr int kTrayCommandDisconnect = 1003;
constexpr UINT kTrayCallbackMessage = WM_APP + 0x42;
constexpr UINT kApplyWindowModeMessage = WM_APP + 0x43;
constexpr UINT kHostBridgeResponseMessage = WM_APP + 0x44;
constexpr UINT kRendererEventMessage = WM_APP + 0x45;
constexpr UINT kSmartCloseResolvedMessage = WM_APP + 0x46;
constexpr UINT kTrayIconId = 1;
constexpr int kCustomTitlebarHeightPx = 34;
constexpr int kWindowControlWidthPx = 88;
constexpr int kWindowControlButtonWidthPx = 44;
constexpr int kWindowCornerRadiusPx = 16;
constexpr UINT kDefaultDpi = 96;

struct RendererDragStart {
  POINT screen{};
  double client_x = 0;
  double client_y = 0;
  double view_width = 0;
  bool has_client_metrics = false;
};

std::wstring wide_from_utf8(const std::string &value) {
  if (value.empty()) {
    return {};
  }
  const int required =
      MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                          static_cast<int>(value.size()), nullptr, 0);
  if (required <= 0) {
    return {};
  }
  std::wstring out(static_cast<std::size_t>(required), L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                      static_cast<int>(value.size()), out.data(), required);
  return out;
}

std::string utf8_from_wide(const wchar_t *value) {
  if (!value) {
    return {};
  }
  const int required =
      WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
  if (required <= 1) {
    return {};
  }
  std::string out(static_cast<std::size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), required, nullptr,
                      nullptr);
  if (!out.empty() && out.back() == '\0') {
    out.pop_back();
  }
  return out;
}

std::string trace_token(std::string value) {
  if (value.empty()) {
    return "-";
  }
  if (value.size() > 96) {
    value.resize(96);
  }
  for (char &ch : value) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte <= ' ' || ch == '"' || ch == '\\') {
      ch = '_';
    }
  }
  return value;
}

std::string window_class_trace_token(HWND hwnd) {
  if (!hwnd) {
    return "-";
  }
  wchar_t class_name[128]{};
  if (GetClassNameW(hwnd, class_name,
                    static_cast<int>(sizeof(class_name) /
                                     sizeof(class_name[0]))) <= 0) {
    return "-";
  }
  return trace_token(utf8_from_wide(class_name));
}

std::string window_title_trace_token(HWND hwnd) {
  if (!hwnd) {
    return "-";
  }
  wchar_t title[160]{};
  if (GetWindowTextW(hwnd, title,
                     static_cast<int>(sizeof(title) / sizeof(title[0]))) <=
      0) {
    return "-";
  }
  return trace_token(utf8_from_wide(title));
}

bool win32_drag_trace_enabled() {
  wchar_t value[8]{};
  if (GetEnvironmentVariableW(
          L"EXV_WIN32_DRAG_TRACE", value,
          static_cast<DWORD>(sizeof(value) / sizeof(value[0]))) > 0) {
    return true;
  }
  wchar_t temp_path[MAX_PATH]{};
  if (GetTempPathW(MAX_PATH, temp_path) == 0) {
    return false;
  }
  const std::wstring sentinel =
      std::wstring(temp_path) + L"exv-win32-drag-trace.enabled";
  return GetFileAttributesW(sentinel.c_str()) != INVALID_FILE_ATTRIBUTES;
}

const char *drag_message_name(UINT message) {
  switch (message) {
  case WM_MOUSEACTIVATE:
    return "WM_MOUSEACTIVATE";
  case WM_ACTIVATE:
    return "WM_ACTIVATE";
  case WM_SETFOCUS:
    return "WM_SETFOCUS";
  case WM_KILLFOCUS:
    return "WM_KILLFOCUS";
  case WM_NCHITTEST:
    return "WM_NCHITTEST";
  case WM_NCMOUSEMOVE:
    return "WM_NCMOUSEMOVE";
  case WM_NCMOUSELEAVE:
    return "WM_NCMOUSELEAVE";
  case WM_NCLBUTTONDOWN:
    return "WM_NCLBUTTONDOWN";
  case WM_NCLBUTTONUP:
    return "WM_NCLBUTTONUP";
  case WM_SYSCOMMAND:
    return "WM_SYSCOMMAND";
  case WM_LBUTTONDOWN:
    return "WM_LBUTTONDOWN";
  case WM_LBUTTONUP:
    return "WM_LBUTTONUP";
  case WM_MOUSEMOVE:
    return "WM_MOUSEMOVE";
  case WM_ENTERSIZEMOVE:
    return "WM_ENTERSIZEMOVE";
  case WM_EXITSIZEMOVE:
    return "WM_EXITSIZEMOVE";
  case WM_CAPTURECHANGED:
    return "WM_CAPTURECHANGED";
  case WM_CANCELMODE:
    return "WM_CANCELMODE";
  default:
    return "other";
  }
}

std::string win32_drag_trace_path() {
  wchar_t temp_path[MAX_PATH]{};
  if (GetTempPathW(MAX_PATH, temp_path) == 0) {
    return "exv-win32-drag-trace.log";
  }
  const std::wstring path =
      std::wstring(temp_path) + L"exv-win32-drag-trace.log";
  return utf8_from_wide(path.c_str());
}

void append_win32_drag_trace(HWND hwnd, const char *phase, UINT message,
                             WPARAM wparam, LPARAM lparam,
                             LRESULT detail = 0) {
  if (!win32_drag_trace_enabled()) {
    return;
  }

  POINT cursor{};
  GetCursorPos(&cursor);
  RECT rect{};
  GetWindowRect(hwnd, &rect);
  const HWND foreground = GetForegroundWindow();

  std::ostringstream line;
  line << GetTickCount64() << " phase=" << phase
       << " msg=" << drag_message_name(message)
       << " hwnd=" << reinterpret_cast<std::uintptr_t>(hwnd)
       << " fg=" << (foreground == hwnd ? 1 : 0)
       << " fg_hwnd=" << reinterpret_cast<std::uintptr_t>(foreground)
       << " fg_class=" << window_class_trace_token(foreground)
       << " fg_title=" << window_title_trace_token(foreground)
       << " capture=" << reinterpret_cast<std::uintptr_t>(GetCapture())
       << " cursor=" << cursor.x << "," << cursor.y << " rect=" << rect.left
       << "," << rect.top << "," << rect.right << "," << rect.bottom
       << " wparam=" << static_cast<std::uintptr_t>(wparam)
       << " lparam=" << static_cast<std::intptr_t>(lparam)
       << " detail=" << static_cast<std::intptr_t>(detail) << "\n";

  std::ofstream out(win32_drag_trace_path(), std::ios::app);
  out << line.str();
}

bool is_supported_external_url(std::string_view url) {
  return url.starts_with("https://") || url.starts_with("http://");
}

bool left_mouse_button_down() {
  return (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
}

bool is_file_uri_path_byte_safe(unsigned char value) {
  return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
         (value >= '0' && value <= '9') || value == '/' || value == ':' ||
         value == '-' || value == '_' || value == '.' || value == '~';
}

std::string percent_encode_file_uri_path(const std::string &value) {
  static constexpr char kHex[] = "0123456789ABCDEF";

  std::string out;
  out.reserve(value.size());
  for (unsigned char byte : value) {
    if (is_file_uri_path_byte_safe(byte)) {
      out.push_back(static_cast<char>(byte));
      continue;
    }
    out.push_back('%');
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
}

#if defined(EXV_BUILD_UI_SHELL)

using GetDpiForSystemFn = UINT(WINAPI *)();
using GetDpiForWindowFn = UINT(WINAPI *)(HWND);

FARPROC user32_proc(const char *name) {
  HMODULE user32 = GetModuleHandleW(L"user32.dll");
  return user32 ? GetProcAddress(user32, name) : nullptr;
}

UINT initial_window_dpi() {
  auto *get_dpi_for_system =
      reinterpret_cast<GetDpiForSystemFn>(user32_proc("GetDpiForSystem"));
  if (get_dpi_for_system) {
    const UINT dpi = get_dpi_for_system();
    if (dpi != 0) {
      return dpi;
    }
  }

  HDC screen = GetDC(nullptr);
  if (!screen) {
    return kDefaultDpi;
  }
  const int dpi = GetDeviceCaps(screen, LOGPIXELSX);
  ReleaseDC(nullptr, screen);
  return dpi > 0 ? static_cast<UINT>(dpi) : kDefaultDpi;
}

UINT dpi_for_window(HWND hwnd) {
  auto *get_dpi_for_window =
      reinterpret_cast<GetDpiForWindowFn>(user32_proc("GetDpiForWindow"));
  if (get_dpi_for_window && hwnd) {
    const UINT dpi = get_dpi_for_window(hwnd);
    if (dpi != 0) {
      return dpi;
    }
  }
  return initial_window_dpi();
}

HICON load_shared_app_icon(HINSTANCE instance, int width, int height) {
  return static_cast<HICON>(LoadImageW(
      instance, MAKEINTRESOURCEW(IDI_EXV_APP), IMAGE_ICON, width, height,
      LR_DEFAULTCOLOR | LR_SHARED));
}

std::wstring temp_bootstrapper_path() {
  wchar_t temp_dir[MAX_PATH] = {};
  const DWORD dir_length = GetTempPathW(MAX_PATH, temp_dir);
  if (dir_length == 0 || dir_length >= MAX_PATH) {
    return {};
  }
  wchar_t temp_file[MAX_PATH] = {};
  if (GetTempFileNameW(temp_dir, L"wv2", 0, temp_file) == 0) {
    return {};
  }
  return temp_file;
}

template <typename T> class ComPtr {
public:
  ComPtr() = default;
  ~ComPtr() { reset(); }

  ComPtr(const ComPtr &) = delete;
  ComPtr &operator=(const ComPtr &) = delete;

  T *get() const { return ptr_; }
  T *operator->() const { return ptr_; }
  explicit operator bool() const { return ptr_ != nullptr; }

  T **put() {
    reset();
    return &ptr_;
  }

  void attach(T *value) {
    reset();
    ptr_ = value;
  }

  void copy_from(T *value) {
    reset();
    ptr_ = value;
    if (ptr_) {
      ptr_->AddRef();
    }
  }

  void reset() {
    if (ptr_) {
      ptr_->Release();
      ptr_ = nullptr;
    }
  }

private:
  T *ptr_ = nullptr;
};

class WebView2Window;

class EnvironmentCompletedHandler final
    : public ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler {
public:
  explicit EnvironmentCompletedHandler(WebView2Window *owner) : owner_(owner) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **object) override;
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG refs = InterlockedDecrement(&refs_);
    if (refs == 0) {
      delete this;
    }
    return refs;
  }
  HRESULT STDMETHODCALLTYPE Invoke(HRESULT error_code,
                                   ICoreWebView2Environment *result) override;

private:
  volatile ULONG refs_ = 1;
  WebView2Window *owner_ = nullptr;
};

class ControllerCompletedHandler final
    : public ICoreWebView2CreateCoreWebView2ControllerCompletedHandler {
public:
  explicit ControllerCompletedHandler(WebView2Window *owner) : owner_(owner) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **object) override;
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG refs = InterlockedDecrement(&refs_);
    if (refs == 0) {
      delete this;
    }
    return refs;
  }
  HRESULT STDMETHODCALLTYPE Invoke(HRESULT error_code,
                                   ICoreWebView2Controller *result) override;

private:
  volatile ULONG refs_ = 1;
  WebView2Window *owner_ = nullptr;
};

class WebMessageReceivedHandler final
    : public ICoreWebView2WebMessageReceivedEventHandler {
public:
  explicit WebMessageReceivedHandler(WebView2Window *owner) : owner_(owner) {}

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **object) override;
  ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }
  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG refs = InterlockedDecrement(&refs_);
    if (refs == 0) {
      delete this;
    }
    return refs;
  }
  HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2 *sender,
                                   ICoreWebView2WebMessageReceivedEventArgs *args) override;

private:
  volatile ULONG refs_ = 1;
  WebView2Window *owner_ = nullptr;
};

class WebView2Window final : public exv::ui_shell::UiWindow {
public:
  ~WebView2Window() override {
    join_smart_close_thread();
    stop_host_bridge_worker();
    if (webview_ && web_message_token_.value != 0) {
      webview_->remove_WebMessageReceived(web_message_token_);
    }
    destroy_tray_icon();
  }

  void set_message_handler(exv::ui_shell::HostMessageHandler handler) override {
    handler_ = std::move(handler);
  }

  int run(const exv::ui_shell::UiWindowConfig &config) override {
    ui_thread_id_ = GetCurrentThreadId();
    active_config_ = config;
    if (!ensure_runtime_available()) {
      return 70;
    }

    const HRESULT coinit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool coinit_ok = SUCCEEDED(coinit);
    if (!coinit_ok && coinit != RPC_E_CHANGED_MODE) {
      return 70;
    }

    if (!create_window()) {
      if (coinit_ok) {
        CoUninitialize();
      }
      return 70;
    }

    create_tray_icon();
    start_host_bridge_worker();

    running_ = true;
    desired_window_visible_ = !active_config_.start_hidden;
    ShowWindow(hwnd_, desired_window_visible_ ? SW_SHOWNORMAL : SW_HIDE);
    if (desired_window_visible_) {
      ensure_window_on_visible_work_area();
      UpdateWindow(hwnd_);
    }

    auto *handler = new EnvironmentCompletedHandler(this);
    const HRESULT created = CreateCoreWebView2EnvironmentWithOptions(
        nullptr, nullptr, nullptr, handler);
    handler->Release();
    if (FAILED(created)) {
      DestroyWindow(hwnd_);
      running_ = false;
      exit_code_ = 70;
    }

    MSG message{};
    while (running_) {
      while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
        if (message.message == WM_QUIT) {
          running_ = false;
          break;
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
      }
      if (active_config_.pump_core_events) {
        active_config_.pump_core_events();
      }
      if (active_config_.poll_wake_requests) {
        active_config_.poll_wake_requests(
            [this]() { restore_or_focus_window(); });
      }
      Sleep(15);
    }

    stop_host_bridge_worker();
    join_smart_close_thread();
    if (hwnd_) {
      DestroyWindow(hwnd_);
      hwnd_ = nullptr;
    }
    destroy_tray_icon();
    if (coinit_ok) {
      CoUninitialize();
    }
    return exit_code_;
  }

  void emit_event(const std::string &event_json) override {
    if (ui_thread_id_ != 0 && GetCurrentThreadId() != ui_thread_id_) {
      {
        std::lock_guard<std::mutex> lock(renderer_event_mutex_);
        renderer_event_queue_.push(event_json);
      }
      if (hwnd_) {
        PostMessageW(hwnd_, kRendererEventMessage, 0, 0);
      }
      return;
    }
    post_renderer_event(event_json);
  }

  void post_host_response(const std::string &response_json) override {
    {
      std::lock_guard<std::mutex> lock(host_response_mutex_);
      host_response_queue_.push(response_json);
    }
    if (hwnd_) {
      PostMessageW(hwnd_, kHostBridgeResponseMessage, 0, 0);
    }
  }

  void post_renderer_event(const std::string &event_json) {
    if (!webview_) {
      pending_events_.push_back(event_json);
      return;
    }
    const std::wstring wide_event = wide_from_utf8(event_json);
    webview_->PostWebMessageAsJson(wide_event.c_str());
  }

  void flush_renderer_events() {
    std::queue<std::string> events;
    {
      std::lock_guard<std::mutex> lock(renderer_event_mutex_);
      events.swap(renderer_event_queue_);
    }
    while (!events.empty()) {
      post_renderer_event(events.front());
      events.pop();
    }
  }

  void post_bridge_success(int id, const nlohmann::ordered_json &data) {
    if (!webview_) {
      return;
    }
    nlohmann::ordered_json out;
    out["id"] = id;
    out["ok"] = true;
    out["data"] = data;
    const std::wstring wide_response = wide_from_utf8(out.dump());
    webview_->PostWebMessageAsJson(wide_response.c_str());
  }

  void post_bridge_error(int id, const char *code, const char *message) {
    if (!webview_) {
      return;
    }
    nlohmann::ordered_json out;
    out["id"] = id;
    out["ok"] = false;
    out["code"] = code;
    out["message"] = message;
    const std::wstring wide_response = wide_from_utf8(out.dump());
    webview_->PostWebMessageAsJson(wide_response.c_str());
  }

  void on_environment_created(HRESULT error_code,
                              ICoreWebView2Environment *environment) {
    if (FAILED(error_code) || !environment || !hwnd_) {
      fail_and_close(L"Unable to create the WebView2 environment.");
      return;
    }
    environment_.copy_from(environment);
    auto *handler = new ControllerCompletedHandler(this);
    const HRESULT hr = create_webview_controller(handler);
    handler->Release();
    if (FAILED(hr)) {
      fail_and_close(L"Unable to create the WebView2 controller.");
    }
  }

  void on_controller_created(HRESULT error_code,
                             ICoreWebView2Controller *controller) {
    if (FAILED(error_code) || !controller) {
      fail_and_close(L"Unable to initialize the WebView2 controller.");
      return;
    }

    controller_.copy_from(controller);
    apply_webview_controller_visibility();
    ICoreWebView2 *raw_webview = nullptr;
    if (FAILED(controller_->get_CoreWebView2(&raw_webview)) || !raw_webview) {
      fail_and_close(L"Unable to access the WebView2 instance.");
      return;
    }
    webview_.attach(raw_webview);

    ComPtr<ICoreWebView2Controller2> controller2;
    const HRESULT controller2_result = controller_->QueryInterface(
        IID_ICoreWebView2Controller2,
        reinterpret_cast<void **>(controller2.put()));
    if (SUCCEEDED(controller2_result) && controller2) {
      COREWEBVIEW2_COLOR transparent{};
      transparent.A = 0;
      transparent.R = 0;
      transparent.G = 0;
      transparent.B = 0;
      controller2->put_DefaultBackgroundColor(transparent);
    }
    configure_non_client_region_support();
    configure_fixed_zoom_behavior();
    configure_browser_accelerator_keys();

    resize_webview();
    if (!configure_packaged_renderer_origin()) {
      fail_and_close(L"Unable to map the packaged renderer assets.");
      return;
    }
    install_renderer_bridge();

    auto *message_handler = new WebMessageReceivedHandler(this);
    const HRESULT add_result =
        webview_->add_WebMessageReceived(message_handler, &web_message_token_);
    message_handler->Release();
    if (FAILED(add_result)) {
      fail_and_close(L"Unable to register the WebView2 message bridge.");
      return;
    }

    const std::wstring uri = webview2_renderer_uri(active_config_.renderer);
    if (uri.empty() || FAILED(webview_->Navigate(uri.c_str()))) {
      fail_and_close(L"Unable to load the packaged renderer.");
      return;
    }

    exit_code_ = 0;
    flush_pending_events();
  }

  HRESULT on_web_message(ICoreWebView2WebMessageReceivedEventArgs *args) {
    if (!args || !webview_) {
      return E_INVALIDARG;
    }

    LPWSTR raw_message = nullptr;
    HRESULT message_result = args->TryGetWebMessageAsString(&raw_message);
    if (FAILED(message_result) || !raw_message) {
      message_result = args->get_WebMessageAsJson(&raw_message);
    }
    if (FAILED(message_result) || !raw_message) {
      return message_result;
    }

    std::string request_json = utf8_from_wide(raw_message);
    CoTaskMemFree(raw_message);
    if (request_json.empty()) {
      return S_OK;
    }

    try {
      auto parsed = nlohmann::json::parse(request_json);
      const std::string action = parsed.value("action", "");
      const int id = parsed.value("id", 0);
      if (action == "window.setMode") {
        std::string mode = "advanced";
        std::uint64_t mode_request = 0;
        if (parsed.contains("payload") && parsed["payload"].is_object()) {
          const auto &payload = parsed["payload"];
          if (payload.contains("mode") && payload["mode"].is_string()) {
            mode = payload["mode"].get<std::string>();
          }
          if (payload.contains("request") &&
              payload["request"].is_number_unsigned()) {
            mode_request = payload["request"].get<std::uint64_t>();
          } else if (payload.contains("request") &&
                     payload["request"].is_number_integer()) {
            const auto request_value = payload["request"].get<std::int64_t>();
            if (request_value > 0) {
              mode_request = static_cast<std::uint64_t>(request_value);
            }
          }
        }
        mode = mode == "minimal" ? "minimal" : "advanced";
        nlohmann::ordered_json out;
        out["id"] = id;
        out["ok"] = true;
        nlohmann::ordered_json data;
        data["mode"] = mode;
        out["data"] = data;
        const std::string response_json = out.dump();
        const std::wstring wide_response = wide_from_utf8(response_json);
        webview_->PostWebMessageAsJson(wide_response.c_str());
        defer_window_mode(mode, mode_request);
        return S_OK;
      }
      if (action == "window.resizeForMode") {
        std::string mode = "advanced";
        std::uint64_t mode_request = 0;
        if (parsed.contains("payload") && parsed["payload"].is_object()) {
          const auto &payload = parsed["payload"];
          if (payload.contains("mode") && payload["mode"].is_string()) {
            mode = payload["mode"].get<std::string>();
          }
          if (payload.contains("request") &&
              payload["request"].is_number_unsigned()) {
            mode_request = payload["request"].get<std::uint64_t>();
          } else if (payload.contains("request") &&
                     payload["request"].is_number_integer()) {
            const auto request_value = payload["request"].get<std::int64_t>();
            if (request_value > 0) {
              mode_request = static_cast<std::uint64_t>(request_value);
            }
          }
        }
        mode = mode == "minimal" ? "minimal" : "advanced";
        if (mode_request > 0) {
          if (mode_request < latest_window_mode_request_) {
            nlohmann::ordered_json data;
            data["ok"] = true;
            data["mode"] = current_window_mode_;
            post_bridge_success(id, data);
            return S_OK;
          }
          latest_window_mode_request_ = mode_request;
        }
        apply_window_mode_once(mode);
        nlohmann::ordered_json data;
        data["ok"] = true;
        data["mode"] = current_window_mode_;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.minimize") {
        if (hwnd_) {
          ShowWindow(hwnd_, SW_MINIMIZE);
        }
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.hideToTray") {
        hide_to_tray();
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.startDrag") {
        std::optional<RendererDragStart> renderer_start;
        if (parsed.contains("payload") && parsed["payload"].is_object()) {
          const auto &payload = parsed["payload"];
          if (payload.contains("screenX") && payload["screenX"].is_number() &&
              payload.contains("screenY") && payload["screenY"].is_number()) {
            RendererDragStart start;
            start.screen = POINT{
                static_cast<LONG>(payload["screenX"].get<double>()),
                static_cast<LONG>(payload["screenY"].get<double>())};
            if (payload.contains("clientX") &&
                payload["clientX"].is_number() &&
                payload.contains("clientY") &&
                payload["clientY"].is_number() &&
                payload.contains("viewWidth") &&
                payload["viewWidth"].is_number()) {
              start.client_x = payload["clientX"].get<double>();
              start.client_y = payload["clientY"].get<double>();
              start.view_width = payload["viewWidth"].get<double>();
              start.has_client_metrics = true;
            }
            renderer_start = start;
          }
        }
        start_window_drag(renderer_start);
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "shell.openExternal") {
        std::string url;
        if (parsed.contains("payload") && parsed["payload"].is_object()) {
          const auto &payload = parsed["payload"];
          if (payload.contains("url") && payload["url"].is_string()) {
            url = payload["url"].get<std::string>();
          }
        }
        if (!is_supported_external_url(url)) {
          post_bridge_error(id, "invalid_url",
                            "Only http and https URLs can be opened.");
          return S_OK;
        }
        const std::wstring wide_url = wide_from_utf8(url);
        const auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(
            hwnd_, L"open", wide_url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
        if (result <= 32) {
          post_bridge_error(id, "open_external_failed",
                            "Unable to open the URL in the default browser.");
          return S_OK;
        }
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "shell.notify") {
        std::string title = "EXV";
        std::string body;
        if (parsed.contains("payload") && parsed["payload"].is_object()) {
          const auto &payload = parsed["payload"];
          if (payload.contains("title") && payload["title"].is_string()) {
            title = payload["title"].get<std::string>();
          }
          if (payload.contains("body") && payload["body"].is_string()) {
            body = payload["body"].get<std::string>();
          }
        }
        show_tray_notification(title, body);
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.requestClose") {
        request_close_decision();
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.getClosePreference") {
        nlohmann::ordered_json data;
        if (const auto preference =
                exv::ui_shell::read_close_preference(active_config_.state_dir)) {
          data["action"] = *preference;
        } else {
          data["action"] = nullptr;
        }
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.setClosePreference") {
        std::string close_action;
        if (parsed.contains("payload") && parsed["payload"].is_object()) {
          const auto &payload = parsed["payload"];
          if (payload.contains("action") && payload["action"].is_string()) {
            close_action = payload["action"].get<std::string>();
          }
        }
        if (!exv::ui_shell::write_close_preference(active_config_.state_dir,
                                                   close_action)) {
          post_bridge_error(id, "invalid_close_preference",
                            "Invalid close preference.");
          return S_OK;
        }
        nlohmann::ordered_json data;
        data["ok"] = true;
        data["action"] = close_action;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.resetClosePreference") {
        if (!exv::ui_shell::clear_close_preference(active_config_.state_dir)) {
          post_bridge_error(id, "close_preference_reset_failed",
                            "Unable to reset close preference.");
          return S_OK;
        }
        nlohmann::ordered_json data;
        data["ok"] = true;
        post_bridge_success(id, data);
        return S_OK;
      }
      if (action == "window.resolveClosePrompt") {
        apply_close_resolution(
            exv::ui_shell::parse_close_prompt_resolution(request_json));
        nlohmann::ordered_json out;
        nlohmann::ordered_json data;
        data["ok"] = true;
        out["id"] = id;
        out["ok"] = true;
        out["data"] = data;
        const std::string response_json = out.dump();
        const std::wstring wide_response = wide_from_utf8(response_json);
        webview_->PostWebMessageAsJson(wide_response.c_str());
        return S_OK;
      }
    } catch (const nlohmann::json::exception &) {
      // Fall through to the worker-backed handler path on parse failure.
    }

    enqueue_host_request(request_json);
    return S_OK;
  }

  void enqueue_host_request(std::string request_json) {
    {
      std::lock_guard<std::mutex> lock(host_request_mutex_);
      host_request_queue_.push(std::move(request_json));
    }
    host_request_cv_.notify_one();
  }

  void start_host_bridge_worker() {
    {
      std::lock_guard<std::mutex> lock(host_request_mutex_);
      host_request_stop_ = false;
    }
    host_request_thread_ = std::thread([this]() { host_bridge_worker_loop(); });
  }

  void stop_host_bridge_worker() {
    {
      std::lock_guard<std::mutex> lock(host_request_mutex_);
      host_request_stop_ = true;
    }
    host_request_cv_.notify_all();
    if (host_request_thread_.joinable()) {
      host_request_thread_.join();
    }
  }

  void host_bridge_worker_loop() {
    for (;;) {
      std::string request_json;
      {
        std::unique_lock<std::mutex> lock(host_request_mutex_);
        host_request_cv_.wait(lock, [this]() {
          return host_request_stop_ || !host_request_queue_.empty();
        });
        if (host_request_stop_ && host_request_queue_.empty()) {
          return;
        }
        request_json = std::move(host_request_queue_.front());
        host_request_queue_.pop();
      }

      std::string response_json =
          handler_ ? handler_(request_json)
                   : R"({"id":0,"ok":false,"code":"host_unavailable","message":"Desktop host bridge is not ready"})";
      if (response_json.empty()) {
        continue;
      }
      {
        std::lock_guard<std::mutex> lock(host_response_mutex_);
        host_response_queue_.push(std::move(response_json));
      }
      if (hwnd_) {
        PostMessageW(hwnd_, kHostBridgeResponseMessage, 0, 0);
      }
    }
  }

  void flush_host_bridge_responses() {
    std::queue<std::string> responses;
    {
      std::lock_guard<std::mutex> lock(host_response_mutex_);
      responses.swap(host_response_queue_);
    }
    while (!responses.empty()) {
      const std::wstring wide_response = wide_from_utf8(responses.front());
      if (webview_) {
        webview_->PostWebMessageAsJson(wide_response.c_str());
      }
      responses.pop();
    }
  }

  void resize_webview() {
    if (!controller_ || !hwnd_) {
      return;
    }
    RECT bounds{};
    GetClientRect(hwnd_, &bounds);
    controller_->put_Bounds(bounds);
  }

  void apply_webview_controller_visibility() {
    if (controller_) {
      controller_->put_IsVisible(desired_window_visible_ ? TRUE : FALSE);
    }
  }

  void apply_rounded_window_region() {
    if (!hwnd_) {
      return;
    }
    RECT window{};
    if (!GetWindowRect(hwnd_, &window)) {
      return;
    }
    const int width = window.right - window.left;
    const int height = window.bottom - window.top;
    if (width <= 0 || height <= 0) {
      return;
    }
    const UINT dpi = dpi_for_window(hwnd_);
    const int radius = MulDiv(kWindowCornerRadiusPx, dpi, kDefaultDpi);
    HRGN region = CreateRoundRectRgn(0, 0, width + 1, height + 1, radius, radius);
    if (!region) {
      return;
    }
    if (SetWindowRgn(hwnd_, region, TRUE) == 0) {
      DeleteObject(region);
    }
  }

  bool create_tray_icon() {
    if (!webview2_should_create_tray_on_start() || !hwnd_ || tray_icon_added_) {
      return true;
    }
    tray_icon_.cbSize = sizeof(tray_icon_);
    tray_icon_.hWnd = hwnd_;
    tray_icon_.uID = kTrayIconId;
    tray_icon_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    tray_icon_.uCallbackMessage = kTrayCallbackMessage;
    tray_icon_.hIcon =
        load_shared_app_icon(instance_, GetSystemMetrics(SM_CXSMICON),
                             GetSystemMetrics(SM_CYSMICON));
    if (!tray_icon_.hIcon) {
      return false;
    }
    wcscpy_s(tray_icon_.szTip, L"EXV");
    tray_icon_added_ = Shell_NotifyIconW(NIM_ADD, &tray_icon_) == TRUE;
    return tray_icon_added_;
  }

  void destroy_tray_icon() {
    if (!tray_icon_added_) {
      return;
    }
    Shell_NotifyIconW(NIM_DELETE, &tray_icon_);
    tray_icon_added_ = false;
  }

  void recreate_tray_icon() {
    if (!hwnd_) {
      return;
    }
    tray_icon_added_ = false;
    create_tray_icon();
  }

  void ensure_window_on_visible_work_area() {
    if (!hwnd_) {
      return;
    }
    RECT rect{};
    if (!GetWindowRect(hwnd_, &rect)) {
      return;
    }
    const int width = rect.right - rect.left;
    const int height = rect.bottom - rect.top;
    if (width <= 0 || height <= 0) {
      return;
    }

    HMONITOR monitor = MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST);
    MONITORINFO info{};
    info.cbSize = sizeof(info);
    if (!monitor || !GetMonitorInfoW(monitor, &info)) {
      return;
    }
    const RECT work = info.rcWork;
    const int work_left = static_cast<int>(work.left);
    const int work_top = static_cast<int>(work.top);
    const int work_right = static_cast<int>(work.right);
    const int work_bottom = static_cast<int>(work.bottom);
    const int work_width = work_right - work_left;
    const int work_height = work_bottom - work_top;
    if (work_width <= 0 || work_height <= 0) {
      return;
    }

    int target_left = rect.left;
    int target_top = rect.top;
    if (width >= work_width) {
      target_left = work_left;
    } else if (rect.right <= work_left || rect.left >= work_right) {
      target_left = work_left + (work_width - width) / 2;
    } else {
      target_left = std::clamp(target_left, work_left, work_right - width);
    }

    if (height >= work_height) {
      target_top = work_top;
    } else if (rect.bottom <= work_top || rect.top >= work_bottom) {
      target_top = work_top + (work_height - height) / 2;
    } else {
      target_top = std::clamp(target_top, work_top, work_bottom - height);
    }

    if (target_left != rect.left || target_top != rect.top) {
      SetWindowPos(hwnd_, nullptr, target_left, target_top, 0, 0,
                   SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
  }

  void restore_or_focus_window() {
    if (!hwnd_) {
      return;
    }
    desired_window_visible_ = true;
    apply_webview_controller_visibility();
    clear_window_control_state();
    if (IsIconic(hwnd_)) {
      ShowWindow(hwnd_, SW_RESTORE);
    }
    ShowWindow(hwnd_, SW_SHOWNORMAL);
    apply_window_mode_once(current_window_mode_);
    ensure_window_on_visible_work_area();
    UpdateWindow(hwnd_);
    SetWindowPos(hwnd_, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetWindowPos(hwnd_, HWND_NOTOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    BringWindowToTop(hwnd_);
    SetActiveWindow(hwnd_);
    SetForegroundWindow(hwnd_);
  }

  void show_from_tray() {
    restore_or_focus_window();
  }

  void start_window_drag(std::optional<RendererDragStart> renderer_start =
                             std::nullopt) {
    if (!hwnd_) {
      return;
    }
    append_win32_drag_trace(hwnd_, "start-drag-enter", 0, 0, 0);

    POINT cursor{};
    if (!GetCursorPos(&cursor)) {
      return;
    }
    const std::optional<POINT> renderer_start_point =
        renderer_start ? std::optional<POINT>(renderer_start->screen)
                       : std::nullopt;
    const std::optional<POINT> renderer_derived_start =
        renderer_client_to_screen(renderer_start);
    const POINT drag_start =
        renderer_derived_start.value_or(renderer_start_point.value_or(cursor));
    append_win32_drag_trace(
        hwnd_,
        renderer_start_point ? "start-drag-renderer-point"
                             : "start-drag-live-point",
        0, renderer_start_point ? 1 : 0,
        MAKELPARAM(drag_start.x, drag_start.y));
    if (renderer_start && renderer_start->has_client_metrics) {
      append_win32_drag_trace(
          hwnd_, "start-drag-renderer-client", 0,
          static_cast<WPARAM>(renderer_start->view_width),
          MAKELPARAM(static_cast<LONG>(renderer_start->client_x),
                     static_cast<LONG>(renderer_start->client_y)));
    }
    if (renderer_derived_start) {
      append_win32_drag_trace(
          hwnd_, "start-drag-derived-screen", 0, 0,
          MAKELPARAM(renderer_derived_start->x, renderer_derived_start->y));
    }

    const LRESULT drag_hit =
        renderer_start && renderer_start->has_client_metrics
            ? renderer_titlebar_hit_test(renderer_start)
            : hit_test_custom_frame_point(drag_start);
    append_win32_drag_trace(hwnd_, "start-drag-hit-test", 0, 0,
                            MAKELPARAM(drag_start.x, drag_start.y), drag_hit);
    if (drag_hit != HTCAPTION) {
      append_win32_drag_trace(hwnd_, "start-drag-reject-hit-test", 0, 0,
                              MAKELPARAM(drag_start.x, drag_start.y),
                              drag_hit);
      return;
    }

    const bool button_down = left_mouse_button_down();
    append_win32_drag_trace(hwnd_, "start-drag-left-button-state", 0,
                            button_down ? 1 : 0,
                            MAKELPARAM(drag_start.x, drag_start.y));
    if (!button_down) {
      append_win32_drag_trace(hwnd_, "start-drag-reject-button-up", 0, 0,
                              MAKELPARAM(drag_start.x, drag_start.y));
      return;
    }

    append_win32_drag_trace(hwnd_, "start-drag-before-foreground", 0, 0, 0);
    if (GetForegroundWindow() != hwnd_) {
      const BOOL top_result =
          SetWindowPos(hwnd_, HWND_TOP, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
      const BOOL foreground_result = SetForegroundWindow(hwnd_);
      append_win32_drag_trace(hwnd_, "start-drag-after-foreground", 0,
                              static_cast<WPARAM>(top_result),
                              static_cast<LPARAM>(foreground_result));
    }

    POINT move_loop_start{};
    if (!GetCursorPos(&move_loop_start)) {
      return;
    }
    append_win32_drag_trace(hwnd_, "start-drag-current-cursor", 0, 0,
                            MAKELPARAM(move_loop_start.x,
                                        move_loop_start.y));
    append_win32_drag_trace(hwnd_, "start-drag-before-send", WM_NCLBUTTONDOWN,
                            HTCAPTION,
                            MAKELPARAM(move_loop_start.x, move_loop_start.y));
    ReleaseCapture();
    SendMessageW(hwnd_, WM_NCLBUTTONDOWN, HTCAPTION,
                 MAKELPARAM(move_loop_start.x, move_loop_start.y));
    append_win32_drag_trace(hwnd_, "start-drag-after-send", WM_NCLBUTTONDOWN,
                            HTCAPTION,
                            MAKELPARAM(move_loop_start.x, move_loop_start.y));
  }

  void quit_from_tray() {
    force_quit_ = true;
    running_ = false;
    if (hwnd_) {
      DestroyWindow(hwnd_);
    }
  }

  void hide_to_tray() {
    desired_window_visible_ = false;
    apply_webview_controller_visibility();
    if (hwnd_) {
      ShowWindow(hwnd_, SW_HIDE);
    }
  }

  void show_tray_notification(const std::string &title,
                              const std::string &body) {
    if (!tray_icon_added_) {
      create_tray_icon();
    }
    if (!tray_icon_added_) {
      return;
    }

    NOTIFYICONDATAW notification = tray_icon_;
    notification.uFlags = NIF_INFO;
    notification.dwInfoFlags = NIIF_INFO;
    const std::wstring wide_title = wide_from_utf8(title.empty() ? "EXV" : title);
    const std::wstring wide_body = wide_from_utf8(body);
    wcsncpy_s(notification.szInfoTitle,
              sizeof(notification.szInfoTitle) /
                  sizeof(notification.szInfoTitle[0]),
              wide_title.c_str(), _TRUNCATE);
    wcsncpy_s(notification.szInfo,
              sizeof(notification.szInfo) / sizeof(notification.szInfo[0]),
              wide_body.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &notification);
  }

  void request_close_decision() {
    if (close_prompt_pending_) {
      show_from_tray();
      return;
    }

    const auto remembered_action =
        exv::ui_shell::read_close_preference(active_config_.state_dir);
    switch (webview2_close_decision_for_connection(
        false, remembered_action.has_value())) {
    case WebView2CloseDecision::QuitImmediately:
      quit_from_tray();
      return;
    case WebView2CloseDecision::ApplyRememberedPreference:
      apply_close_resolution({*remembered_action, false});
      return;
    case WebView2CloseDecision::Prompt:
      break;
    }

    close_prompt_pending_ = true;
    emit_event(R"({"type":"close-request","data":{}})");
  }

  void apply_close_resolution(
      const exv::ui_shell::ClosePromptResolution &resolution) {
    close_prompt_pending_ = false;
    if (resolution.remember) {
      exv::ui_shell::write_close_preference(active_config_.state_dir,
                                                resolution.action);
    }

    if (resolution.action == "tray") {
      hide_to_tray();
    } else if (resolution.action == "quit") {
      quit_from_tray();
    } else if (resolution.action == "smart") {
      begin_smart_close_resolution();
    } else {
      show_from_tray();
    }
  }

  void begin_smart_close_resolution() {
    hide_to_tray();
    if (!hwnd_) {
      quit_from_tray();
      return;
    }
    if (smart_close_pending_) {
      return;
    }
    join_smart_close_thread();
    smart_close_pending_ = true;

    const HWND hwnd = hwnd_;
    auto is_vpn_connected = active_config_.is_vpn_connected;
    smart_close_thread_ = std::thread([hwnd, is_vpn_connected]() mutable {
      bool connected = false;
      if (is_vpn_connected) {
        try {
          connected = is_vpn_connected();
        } catch (...) {
          connected = false;
        }
      }
      PostMessageW(hwnd, kSmartCloseResolvedMessage, connected ? 1 : 0, 0);
    });
  }

  void handle_smart_close_resolved(bool vpn_connected) {
    smart_close_pending_ = false;
    join_smart_close_thread();
    if (!vpn_connected) {
      quit_from_tray();
    }
  }

  void join_smart_close_thread() {
    if (smart_close_thread_.joinable()) {
      smart_close_thread_.join();
    }
  }

  void defer_window_mode(const std::string &mode, std::uint64_t request) {
    if (request > 0) {
      if (request < latest_window_mode_request_) {
        return;
      }
      latest_window_mode_request_ = request;
    }
    pending_window_mode_ = mode == "minimal" ? "minimal" : "advanced";
    if (!hwnd_ || !PostMessageW(hwnd_, kApplyWindowModeMessage, 0, 0)) {
      apply_deferred_window_mode();
    }
  }

  void apply_deferred_window_mode() {
    std::string mode = pending_window_mode_.empty() ? current_window_mode_
                                                    : pending_window_mode_;
    pending_window_mode_.clear();
    apply_window_mode(mode);
  }

  void apply_window_mode(const std::string &mode) {
    apply_window_mode_once(mode);
  }

  void apply_window_mode_once(const std::string &mode) {
    current_window_mode_ = mode == "minimal" ? "minimal" : "advanced";
    const UINT dpi = hwnd_ ? dpi_for_window(hwnd_) : kDefaultDpi;
    const auto bounds =
        webview2_window_mode_bounds_for_dpi(current_window_mode_, dpi);
    if (!hwnd_) {
      return;
    }
    SetWindowPos(hwnd_, nullptr, 0, 0, bounds.width, bounds.height,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    apply_rounded_window_region();
    resize_webview();
  }

  void apply_dpi_changed_bounds(UINT dpi, const RECT *suggested_rect) {
    if (!hwnd_) {
      return;
    }
    const auto bounds =
        webview2_window_mode_bounds_for_dpi(current_window_mode_, dpi);
    if (suggested_rect) {
      SetWindowPos(hwnd_, nullptr, suggested_rect->left, suggested_rect->top,
                   bounds.width, bounds.height, SWP_NOZORDER | SWP_NOACTIVATE);
    } else {
      SetWindowPos(hwnd_, nullptr, 0, 0, bounds.width, bounds.height,
                   SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    apply_rounded_window_region();
    resize_webview();
  }

  static bool is_window_control_hit(LRESULT hit) {
    return hit == HTMINBUTTON || hit == HTCLOSE;
  }

  static const char *window_control_name(LRESULT hit) {
    if (hit == HTMINBUTTON) {
      return "minimize";
    }
    if (hit == HTCLOSE) {
      return "close";
    }
    return nullptr;
  }

  LRESULT control_button_hit_test(int content_x, int content_y,
                                  int content_width, UINT dpi) const {
    const int titlebar_height =
        MulDiv(kCustomTitlebarHeightPx, dpi, kDefaultDpi);
    if (content_y < 0 || content_y >= titlebar_height) {
      return HTCLIENT;
    }

    const int controls_width =
        MulDiv(kWindowControlWidthPx, dpi, kDefaultDpi);
    const int button_width =
        MulDiv(kWindowControlButtonWidthPx, dpi, kDefaultDpi);
    const int controls_left = content_width - controls_width;
    if (content_x < controls_left || content_x >= content_width) {
      return HTCLIENT;
    }

    if (content_x < controls_left + button_width) {
      return HTMINBUTTON;
    }
    return HTCLOSE;
  }

  void track_non_client_mouse_leave() {
    if (!hwnd_ || tracking_non_client_mouse_leave_) {
      return;
    }
    TRACKMOUSEEVENT track{};
    track.cbSize = sizeof(track);
    track.dwFlags = TME_LEAVE | TME_NONCLIENT;
    track.hwndTrack = hwnd_;
    tracking_non_client_mouse_leave_ = TrackMouseEvent(&track) == TRUE;
  }

  void emit_window_control_state(LRESULT hit, bool pressed) {
    if (!is_window_control_hit(hit)) {
      hit = HTCLIENT;
      pressed = false;
    }
    if (window_control_state_hit_ == hit &&
        window_control_state_pressed_ == pressed) {
      return;
    }
    window_control_state_hit_ = hit;
    window_control_state_pressed_ = pressed;

    nlohmann::ordered_json event;
    event["type"] = "window-control-state";
    event["data"] = nlohmann::ordered_json::object();
    if (const char *control = window_control_name(hit)) {
      event["data"]["control"] = control;
    } else {
      event["data"]["control"] = nullptr;
    }
    event["data"]["pressed"] = pressed;
    emit_event(event.dump());
  }

  void clear_window_control_state() {
    active_window_control_hit_ = HTCLIENT;
    emit_window_control_state(HTCLIENT, false);
  }

  void invoke_window_control(LRESULT hit) {
    if (hit == HTMINBUTTON) {
      ShowWindow(hwnd_, SW_MINIMIZE);
    } else if (hit == HTCLOSE) {
      request_close_decision();
    }
  }

  LRESULT window_control_hit_from_client_lparam(LPARAM lparam) const {
    if (!hwnd_) {
      return HTCLIENT;
    }
    POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
    ClientToScreen(hwnd_, &point);
    const LRESULT hit = hit_test_custom_frame_point(point);
    return is_window_control_hit(hit) ? hit : HTCLIENT;
  }

  void begin_window_control_press(LRESULT hit) {
    if (!hwnd_ || !is_window_control_hit(hit)) {
      return;
    }
    active_window_control_hit_ = hit;
    HWND capture_target = hwnd_;
    SetCapture(capture_target);
    track_non_client_mouse_leave();
    emit_window_control_state(hit, true);
  }

  void update_window_control_press(LRESULT hit) {
    if (!is_window_control_hit(active_window_control_hit_)) {
      return;
    }
    const bool still_pressed = hit == active_window_control_hit_;
    emit_window_control_state(still_pressed ? active_window_control_hit_
                                            : HTCLIENT,
                              still_pressed);
  }

  void finish_window_control_press(LRESULT hit) {
    if (!is_window_control_hit(active_window_control_hit_)) {
      return;
    }
    const LRESULT active_hit = active_window_control_hit_;
    active_window_control_hit_ = HTCLIENT;
    if (GetCapture() == hwnd_) {
      ReleaseCapture();
    }
    emit_window_control_state(hit == active_hit ? active_hit : HTCLIENT,
                              false);
    if (hit == active_hit) {
      invoke_window_control(active_hit);
    }
  }

  LRESULT hit_test_custom_frame_point(POINT point) const {
    if (!hwnd_) {
      return HTCLIENT;
    }
    RECT window{};
    if (!GetWindowRect(hwnd_, &window)) {
      return HTCLIENT;
    }
    const int x = point.x - window.left;
    const int y = point.y - window.top;
    const int width = window.right - window.left;
    const int height = window.bottom - window.top;
    const UINT dpi = dpi_for_window(hwnd_);
    const int shadow_margin =
        MulDiv(exv::ui_shell::kWindowShadowMarginPx, dpi, kDefaultDpi);
    const int content_x = x - shadow_margin;
    const int content_y = y - shadow_margin;
    const int content_width = width - shadow_margin * 2;
    const int content_height = height - shadow_margin * 2;
    if (content_width <= 0 || content_height <= 0 || content_x < 0 ||
        content_y < 0 || content_x >= content_width ||
        content_y >= content_height) {
      return HTNOWHERE;
    }
    const int titlebar_height =
        MulDiv(kCustomTitlebarHeightPx, dpi, kDefaultDpi);
    if (content_y >= 0 && content_y < titlebar_height) {
      const LRESULT control_hit =
          control_button_hit_test(content_x, content_y, content_width, dpi);
      if (control_hit != HTCLIENT) {
        return control_hit;
      }
      return HTCAPTION;
    }
    return HTCLIENT;
  }

  std::optional<POINT> renderer_client_to_screen(
      const std::optional<RendererDragStart> &renderer_start) const {
    if (!hwnd_ || !renderer_start || !renderer_start->has_client_metrics ||
        renderer_start->client_x < 0 || renderer_start->client_y < 0) {
      return std::nullopt;
    }
    RECT window{};
    if (!GetWindowRect(hwnd_, &window)) {
      return std::nullopt;
    }
    const UINT dpi = dpi_for_window(hwnd_);
    return POINT{
        window.left +
            MulDiv(static_cast<int>(renderer_start->client_x), dpi,
                   kDefaultDpi),
        window.top +
            MulDiv(static_cast<int>(renderer_start->client_y), dpi,
                   kDefaultDpi)};
  }

  LRESULT renderer_titlebar_hit_test(
      const std::optional<RendererDragStart> &renderer_start) const {
    if (!renderer_start || !renderer_start->has_client_metrics ||
        renderer_start->view_width <= 0 || renderer_start->client_x < 0 ||
        renderer_start->client_y < 0 ||
        renderer_start->client_x >= renderer_start->view_width) {
      return HTCLIENT;
    }
    if (renderer_start->client_y >= kCustomTitlebarHeightPx) {
      return HTCLIENT;
    }
    const double controls_left =
        renderer_start->view_width - kWindowControlWidthPx;
    if (renderer_start->client_x >= controls_left &&
        renderer_start->client_x < renderer_start->view_width) {
      return HTCLIENT;
    }
    return HTCAPTION;
  }

  LRESULT hit_test_custom_frame(LPARAM lparam) const {
    return hit_test_custom_frame_point(
        POINT{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)});
  }

  void show_tray_menu() {
    HMENU menu = CreatePopupMenu();
    if (!menu) {
      return;
    }
    const auto snapshot = active_config_.tray_status_snapshot_provider
                              ? active_config_.tray_status_snapshot_provider()
                              : exv::ui_shell::TrayStatusSnapshot{};
    for (const auto &item : webview2_tray_menu_model(snapshot)) {
      if (item.separator) {
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
      } else if (!item.label.empty()) {
        AppendMenuW(menu, MF_STRING | (item.enabled ? 0 : MF_GRAYED),
                    static_cast<UINT_PTR>(item.command_id),
                    item.label.c_str());
      }
    }
    POINT cursor{};
    GetCursorPos(&cursor);
    SetForegroundWindow(hwnd_);
    const UINT command = TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, hwnd_,
        nullptr);
    DestroyMenu(menu);
    if (command == kTrayCommandShow) {
      show_from_tray();
    } else if (command == kTrayCommandDisconnect) {
      if (active_config_.disconnect_vpn_in_background) {
        active_config_.disconnect_vpn_in_background();
      }
    } else if (command == kTrayCommandQuit) {
      quit_from_tray();
    }
  }

private:
  void enable_host_input_processing(ICoreWebView2ControllerOptions *options) {
    if (!options) {
      return;
    }

    ComPtr<ICoreWebView2ControllerOptions4> options4;
    const HRESULT options4_result = options->QueryInterface(
        IID_ICoreWebView2ControllerOptions4,
        reinterpret_cast<void **>(options4.put()));
    if (SUCCEEDED(options4_result) && options4) {
      options4->put_AllowHostInputProcessing(TRUE);
    }
  }

  HRESULT create_webview_controller(
      ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *handler) {
    if (!environment_ || !hwnd_) {
      return E_FAIL;
    }

    ComPtr<ICoreWebView2Environment10> environment10;
    const HRESULT environment10_result = environment_->QueryInterface(
        IID_ICoreWebView2Environment10,
        reinterpret_cast<void **>(environment10.put()));
    if (SUCCEEDED(environment10_result) && environment10) {
      ComPtr<ICoreWebView2ControllerOptions> options;
      const HRESULT options_result =
          environment10->CreateCoreWebView2ControllerOptions(options.put());
      if (SUCCEEDED(options_result) && options) {
        enable_host_input_processing(options.get());
        const HRESULT options_controller_result =
            environment10->CreateCoreWebView2ControllerWithOptions(
                hwnd_, options.get(), handler);
        if (SUCCEEDED(options_controller_result)) {
          return options_controller_result;
        }
      }
    }

    return environment_->CreateCoreWebView2Controller(hwnd_, handler);
  }

  void configure_non_client_region_support() {
    if (!webview_) {
      return;
    }

    ICoreWebView2Settings *raw_settings = nullptr;
    if (FAILED(webview_->get_Settings(&raw_settings)) || !raw_settings) {
      return;
    }

    ComPtr<ICoreWebView2Settings> settings;
    settings.attach(raw_settings);
    ComPtr<ICoreWebView2Settings9> settings9;
    const HRESULT settings9_result = settings->QueryInterface(
        IID_ICoreWebView2Settings9,
        reinterpret_cast<void **>(settings9.put()));
    if (SUCCEEDED(settings9_result) && settings9) {
      settings9->put_IsNonClientRegionSupportEnabled(TRUE);
    }
  }

  void configure_fixed_zoom_behavior() {
    if (controller_) {
      controller_->put_ZoomFactor(1.0);
    }
    if (!webview_) {
      return;
    }

    ICoreWebView2Settings *raw_settings = nullptr;
    if (FAILED(webview_->get_Settings(&raw_settings)) || !raw_settings) {
      return;
    }

    ComPtr<ICoreWebView2Settings> settings;
    settings.attach(raw_settings);
    settings->put_IsZoomControlEnabled(FALSE);
  }

  void configure_browser_accelerator_keys() {
    if (!webview_) {
      return;
    }

    ICoreWebView2Settings *raw_settings = nullptr;
    if (FAILED(webview_->get_Settings(&raw_settings)) || !raw_settings) {
      return;
    }

    ComPtr<ICoreWebView2Settings> settings;
    settings.attach(raw_settings);
    ComPtr<ICoreWebView2Settings3> settings3;
    const HRESULT settings3_result = settings->QueryInterface(
        IID_ICoreWebView2Settings3,
        reinterpret_cast<void **>(settings3.put()));
    if (SUCCEEDED(settings3_result) && settings3) {
      settings3->put_AreBrowserAcceleratorKeysEnabled(FALSE);
    }
  }

  bool configure_packaged_renderer_origin() {
    if (active_config_.renderer.kind ==
        exv::ui_shell::RendererAssetKind::DevServer) {
      return true;
    }

    ComPtr<ICoreWebView2_3> webview3;
    const HRESULT interface_result = webview_->QueryInterface(
        IID_ICoreWebView2_3, reinterpret_cast<void **>(webview3.put()));
    if (FAILED(interface_result) || !webview3) {
      return false;
    }

    const std::wstring folder =
        webview2_packaged_renderer_folder(active_config_.renderer);
    if (folder.empty()) {
      return false;
    }
    return SUCCEEDED(webview3->SetVirtualHostNameToFolderMapping(
        kPackagedRendererHostWide, folder.c_str(),
        COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY));
  }

  bool ensure_runtime_available() {
    if (detect_webview2_runtime().installed) {
      return true;
    }

    const int choice = MessageBoxW(
        nullptr,
        L"Microsoft Edge WebView2 Runtime is required. Download and install "
        L"the Evergreen Runtime now?",
        L"EXV", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
    if (choice != IDYES) {
      return false;
    }

    const std::wstring installer_path = temp_bootstrapper_path();
    if (installer_path.empty()) {
      return false;
    }
    const std::string installer_path_utf8 = utf8_from_wide(installer_path.c_str());
    return run_webview2_evergreen_bootstrapper(
               "https://go.microsoft.com/fwlink/?linkid=2124703",
               installer_path_utf8) &&
           detect_webview2_runtime().installed;
  }

  bool create_window() {
    const auto bounds =
        webview2_window_mode_bounds_for_dpi("advanced", initial_window_dpi());
    instance_ = GetModuleHandleW(nullptr);
    taskbar_created_message_ =
        RegisterWindowMessageW(webview2_taskbar_created_message_name().c_str());
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = &WebView2Window::window_proc;
    window_class.hInstance = instance_;
    window_class.lpszClassName = L"EXVWebViewShellWindow";
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.hIcon =
        load_shared_app_icon(instance_, GetSystemMetrics(SM_CXICON),
                             GetSystemMetrics(SM_CYICON));
    window_class.hIconSm =
        load_shared_app_icon(instance_, GetSystemMetrics(SM_CXSMICON),
                             GetSystemMetrics(SM_CYSMICON));
    RegisterClassExW(&window_class);

    hwnd_ = CreateWindowExW(0, window_class.lpszClassName, L"EXV",
                            kFixedWindowStyle, CW_USEDEFAULT, CW_USEDEFAULT,
                            bounds.width, bounds.height, nullptr, nullptr,
                            instance_, this);
    if (hwnd_) {
      install_custom_frame_style();
      apply_rounded_window_region();
    }
    return hwnd_ != nullptr;
  }

  void install_custom_frame_style() {
    if (!hwnd_) {
      return;
    }
    const LONG_PTR style = GetWindowLongPtrW(hwnd_, GWL_STYLE);
    SetWindowLongPtrW(hwnd_, GWL_STYLE, style & ~WS_CAPTION);
    SetWindowPos(hwnd_, nullptr, 0, 0, 0, 0,
                 SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER |
                     SWP_NOACTIVATE);
  }

  void install_renderer_bridge() {
    static constexpr wchar_t kBridgeScript[] = LR"JS(
(() => {
  if (window.exv || !window.chrome || !window.chrome.webview) return;
  let nextId = 1;
  const pending = new Map();
  const subscribers = new Set();
  function rpc(action, payload) {
    const id = nextId++;
    const request = { id, action, payload: payload ?? {} };
    window.chrome.webview.postMessage(JSON.stringify(request));
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
    });
  }
  function unsupported(name) {
    return Promise.reject(new Error(`${name} is not available in the native WebView shell yet.`));
  }
  window.chrome.webview.addEventListener('message', (event) => {
    const message = event.data;
    if (message && typeof message.id === 'number' && pending.has(message.id)) {
      const callbacks = pending.get(message.id);
      pending.delete(message.id);
      if (message.ok) callbacks.resolve(message.data);
      else {
        const error = new Error(message.message || 'Desktop RPC failed');
        error.code = message.code;
        callbacks.reject(error);
      }
      return;
    }
    subscribers.forEach((handler) => handler(message));
  });
  window.exv = {
    status: { get: () => rpc('status.get') },
    vpn: {
      connect: (password) => rpc('vpn.connect', { password }),
      disconnect: () => rpc('vpn.disconnect'),
      connectElevated: (password) => rpc('vpn.connect', { password }),
      disconnectElevated: (backend) => rpc('vpn.disconnect', { backend }),
      authInteraction: () => rpc('vpn.authInteraction.get'),
      respondAuthInteraction: (id, value) => rpc('vpn.authInteraction.respond', { id, value }),
    },
    config: {
      getAuth: () => rpc('config.getAuth'),
      saveAuth: (input) => rpc('config.saveAuth', input),
      getSettings: () => rpc('config.getSettings'),
      saveSettings: (input) => rpc('config.saveSettings', input),
      getKey: () => rpc('config.getKey'),
      importConfig: (input) => rpc('config.import', input ?? {}),
      exportConfig: (input) => rpc('config.export', input ?? {}),
      reset: (confirm) => rpc('config.reset', { confirm }),
    },
    routes: {
      list: () => rpc('routes.list'),
      add: (cidr) => rpc('routes.add', { cidr }),
      remove: (cidr) => rpc('routes.remove', { cidr }),
      reset: () => rpc('routes.reset'),
    },
    service: {
      status: () => rpc('service.status'),
      install: () => rpc('service.install'),
      uninstall: () => rpc('service.uninstall'),
      repair: () => rpc('service.repair'),
    },
    cli: {
      status: () => rpc('cli.status'),
      install: () => rpc('cli.install'),
      uninstall: () => rpc('cli.uninstall'),
    },
    logs: { list: (options) => rpc('logs.list', options ?? {}) },
    runtime: { status: () => rpc('runtime.status') },
    drivers: {
      status: () => rpc('drivers.status'),
      install: (driver) => rpc('drivers.install', { driver }),
    },
    key: {
      status: () => rpc('key.status'),
      reset: (confirm) => rpc('key.reset', { confirm }),
    },
    maintenance: {
      inspectCore: () => rpc('maintenance.inspectCore'),
      killStaleCore: (confirm) => rpc('maintenance.killStaleCore', { confirm }),
    },
    window: {
      setMode: (mode, request) => rpc('window.resizeForMode', { mode, request }),
      resizeForMode: (mode, request) => rpc('window.resizeForMode', { mode, request }),
      minimize: () => rpc('window.minimize'),
      hideToTray: () => rpc('window.hideToTray'),
      requestClose: () => rpc('window.requestClose'),
      getClosePreference: () => rpc('window.getClosePreference'),
      setClosePreference: (action) => rpc('window.setClosePreference', { action }),
      resetClosePreference: () => rpc('window.resetClosePreference'),
      resolveClosePrompt: (result) => rpc('window.resolveClosePrompt', { result }),
      startDrag: (drag) => rpc('window.startDrag', drag ?? {}),
    },
    shell: {
      openExternal: (url) => rpc('shell.openExternal', { url }),
      notify: (payload) => rpc('shell.notify', payload ?? {}),
    },
    modal: {
      serviceInstallPrompt: () => Promise.resolve('dismiss'),
      passwordPrompt: (message) => Promise.resolve(window.prompt(message) ?? null),
      confirmPrompt: (message) => Promise.resolve(window.confirm(message)),
      getPayload: () => Promise.resolve(null),
      resolve: () => Promise.resolve(),
    },
    events: {
      subscribe: (handler) => {
        subscribers.add(handler);
        return () => subscribers.delete(handler);
      },
    },
    core: {
      restart: () => rpc('core.restart'),
      quit: () => { window.close(); return Promise.resolve(); },
    },
  };
})();
)JS";
    webview_->AddScriptToExecuteOnDocumentCreated(kBridgeScript, nullptr);
  }

  void flush_pending_events() {
    for (const std::string &event_json : pending_events_) {
      emit_event(event_json);
    }
    pending_events_.clear();
  }

  void fail_and_close(const wchar_t *message) {
    MessageBoxW(hwnd_, message, L"EXV", MB_ICONERROR | MB_OK);
    exit_code_ = 70;
    running_ = false;
    if (hwnd_) {
      DestroyWindow(hwnd_);
    }
  }

  static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam,
                                      LPARAM lparam) {
    WebView2Window *self =
        reinterpret_cast<WebView2Window *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
      auto *create = reinterpret_cast<CREATESTRUCTW *>(lparam);
      self = reinterpret_cast<WebView2Window *>(create->lpCreateParams);
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
      self->hwnd_ = hwnd;
    }

    if (self) {
      if (self->taskbar_created_message_ != 0 &&
          message == self->taskbar_created_message_) {
        self->recreate_tray_icon();
        return 0;
      }
      if (message == WM_MOUSEACTIVATE || message == WM_ACTIVATE ||
          message == WM_SETFOCUS || message == WM_KILLFOCUS ||
          message == WM_NCHITTEST || message == WM_NCMOUSEMOVE ||
          message == WM_NCMOUSELEAVE || message == WM_NCLBUTTONDOWN ||
          message == WM_NCLBUTTONUP || message == WM_LBUTTONUP ||
          message == WM_MOUSEMOVE || message == WM_SYSCOMMAND ||
          message == WM_ENTERSIZEMOVE || message == WM_EXITSIZEMOVE ||
          message == WM_CAPTURECHANGED || message == WM_CANCELMODE) {
        append_win32_drag_trace(hwnd, "wndproc-enter", message, wparam,
                                lparam);
      }
      switch (message) {
      case WM_MOUSEACTIVATE:
        return MA_ACTIVATE;
      case WM_NCCALCSIZE:
        return 0;
      case WM_NCHITTEST: {
        const LRESULT hit = self->hit_test_custom_frame(lparam);
        append_win32_drag_trace(hwnd, "nchittest-result", message, wparam,
                                lparam, hit);
        if (is_window_control_hit(hit)) {
          self->track_non_client_mouse_leave();
          if (!is_window_control_hit(self->active_window_control_hit_)) {
            self->emit_window_control_state(hit, false);
          }
          return hit;
        }
        if (!is_window_control_hit(self->active_window_control_hit_)) {
          self->emit_window_control_state(HTCLIENT, false);
        }
        if (hit != HTCLIENT) {
          return hit;
        }
        break;
      }
      case WM_NCMOUSEMOVE:
        if (is_window_control_hit(static_cast<LRESULT>(wparam))) {
          self->track_non_client_mouse_leave();
          if (!is_window_control_hit(self->active_window_control_hit_)) {
            self->emit_window_control_state(static_cast<LRESULT>(wparam),
                                            false);
          }
        } else if (!is_window_control_hit(self->active_window_control_hit_)) {
          self->emit_window_control_state(HTCLIENT, false);
        }
        break;
      case WM_NCLBUTTONDOWN:
        if (is_window_control_hit(static_cast<LRESULT>(wparam))) {
          self->begin_window_control_press(static_cast<LRESULT>(wparam));
          return 0;
        }
        break;
      case WM_MOUSEMOVE:
        if (is_window_control_hit(self->active_window_control_hit_)) {
          self->update_window_control_press(
              self->window_control_hit_from_client_lparam(lparam));
          return 0;
        }
        break;
      case WM_LBUTTONUP:
        if (is_window_control_hit(self->active_window_control_hit_)) {
          self->finish_window_control_press(
              self->window_control_hit_from_client_lparam(lparam));
          return 0;
        }
        break;
      case WM_NCLBUTTONUP:
        if (is_window_control_hit(self->active_window_control_hit_)) {
          const LRESULT hit = is_window_control_hit(static_cast<LRESULT>(wparam))
                                  ? static_cast<LRESULT>(wparam)
                                  : HTCLIENT;
          self->finish_window_control_press(hit);
          return 0;
        }
        break;
      case WM_NCMOUSELEAVE:
        self->tracking_non_client_mouse_leave_ = false;
        if (!is_window_control_hit(self->active_window_control_hit_)) {
          self->emit_window_control_state(HTCLIENT, false);
        }
        break;
      case WM_ENTERSIZEMOVE:
        append_win32_drag_trace(hwnd, "enter-size-move", message, wparam,
                                lparam);
        break;
      case WM_EXITSIZEMOVE:
        append_win32_drag_trace(hwnd, "exit-size-move", message, wparam,
                                lparam);
        break;
      case WM_CAPTURECHANGED:
        if (reinterpret_cast<HWND>(lparam) != hwnd) {
          self->clear_window_control_state();
        }
        append_win32_drag_trace(hwnd, "capture-changed", message, wparam,
                                lparam);
        break;
      case WM_CANCELMODE:
        self->clear_window_control_state();
        append_win32_drag_trace(hwnd, "cancel-mode", message, wparam, lparam);
        break;
      case WM_SYSCOMMAND:
        if ((wparam & 0xFFF0) == SC_MINIMIZE ||
            (wparam & 0xFFF0) == SC_CLOSE) {
          self->clear_window_control_state();
        }
        break;
      case WM_SIZE:
        self->apply_rounded_window_region();
        self->resize_webview();
        return 0;
      case WM_DPICHANGED:
        self->apply_dpi_changed_bounds(
            static_cast<UINT>(HIWORD(wparam)),
            reinterpret_cast<const RECT *>(lparam));
        return 0;
      case WM_CLOSE:
        self->clear_window_control_state();
        if (self->force_quit_) {
          DestroyWindow(hwnd);
        } else {
          self->request_close_decision();
        }
        return 0;
      case WM_DESTROY:
        self->running_ = false;
        return 0;
      case kTrayCallbackMessage:
        if (lparam == WM_LBUTTONUP) {
          self->show_from_tray();
        } else if (lparam == WM_RBUTTONUP || lparam == WM_CONTEXTMENU) {
          self->show_tray_menu();
        }
        return 0;
      case kApplyWindowModeMessage:
        self->apply_deferred_window_mode();
        return 0;
      case kHostBridgeResponseMessage:
        self->flush_host_bridge_responses();
        return 0;
      case kRendererEventMessage:
        self->flush_renderer_events();
        return 0;
      case kSmartCloseResolvedMessage:
        self->handle_smart_close_resolved(wparam != 0);
        return 0;
      default:
        break;
      }
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
  }

  HINSTANCE instance_ = nullptr;
  HWND hwnd_ = nullptr;
  bool running_ = false;
  int exit_code_ = 70;
  EventRegistrationToken web_message_token_{};
  exv::ui_shell::UiWindowConfig active_config_;
  exv::ui_shell::HostMessageHandler handler_;
  ComPtr<ICoreWebView2Environment> environment_;
  ComPtr<ICoreWebView2Controller> controller_;
  ComPtr<ICoreWebView2> webview_;
  std::vector<std::string> pending_events_;
  std::mutex renderer_event_mutex_;
  std::queue<std::string> renderer_event_queue_;
  std::mutex host_request_mutex_;
  std::condition_variable host_request_cv_;
  std::queue<std::string> host_request_queue_;
  std::mutex host_response_mutex_;
  std::queue<std::string> host_response_queue_;
  std::thread host_request_thread_;
  std::thread smart_close_thread_;
  NOTIFYICONDATAW tray_icon_{};
  DWORD ui_thread_id_ = 0;
  UINT taskbar_created_message_ = 0;
  std::string current_window_mode_ = "advanced";
  std::string pending_window_mode_;
  std::uint64_t latest_window_mode_request_ = 0;
  bool host_request_stop_ = false;
  bool tray_icon_added_ = false;
  bool force_quit_ = false;
  bool close_prompt_pending_ = false;
  bool smart_close_pending_ = false;
  bool desired_window_visible_ = false;
  bool tracking_non_client_mouse_leave_ = false;
  LRESULT active_window_control_hit_ = HTCLIENT;
  LRESULT window_control_state_hit_ = HTCLIENT;
  bool window_control_state_pressed_ = false;
};

HRESULT EnvironmentCompletedHandler::QueryInterface(REFIID riid, void **object) {
  if (!object) {
    return E_POINTER;
  }
  if (IsEqualIID(riid, IID_IUnknown) ||
      IsEqualIID(riid, IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler)) {
    *object = static_cast<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *>(this);
    AddRef();
    return S_OK;
  }
  *object = nullptr;
  return E_NOINTERFACE;
}

HRESULT EnvironmentCompletedHandler::Invoke(
    HRESULT error_code, ICoreWebView2Environment *result) {
  owner_->on_environment_created(error_code, result);
  return S_OK;
}

HRESULT ControllerCompletedHandler::QueryInterface(REFIID riid, void **object) {
  if (!object) {
    return E_POINTER;
  }
  if (IsEqualIID(riid, IID_IUnknown) ||
      IsEqualIID(riid, IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler)) {
    *object = static_cast<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *>(this);
    AddRef();
    return S_OK;
  }
  *object = nullptr;
  return E_NOINTERFACE;
}

HRESULT ControllerCompletedHandler::Invoke(HRESULT error_code,
                                           ICoreWebView2Controller *result) {
  owner_->on_controller_created(error_code, result);
  return S_OK;
}

HRESULT WebMessageReceivedHandler::QueryInterface(REFIID riid, void **object) {
  if (!object) {
    return E_POINTER;
  }
  if (IsEqualIID(riid, IID_IUnknown) ||
      IsEqualIID(riid, IID_ICoreWebView2WebMessageReceivedEventHandler)) {
    *object = static_cast<ICoreWebView2WebMessageReceivedEventHandler *>(this);
    AddRef();
    return S_OK;
  }
  *object = nullptr;
  return E_NOINTERFACE;
}

HRESULT WebMessageReceivedHandler::Invoke(
    ICoreWebView2 *, ICoreWebView2WebMessageReceivedEventArgs *args) {
  return owner_->on_web_message(args);
}

#else

class WebView2Window final : public exv::ui_shell::UiWindow {
public:
  void set_message_handler(exv::ui_shell::HostMessageHandler handler) override {
    handler_ = std::move(handler);
  }

  int run(const exv::ui_shell::UiWindowConfig &) override {
    return 70;
  }

  void emit_event(const std::string &event_json) override {
    last_event_json_ = event_json;
  }

private:
  exv::ui_shell::HostMessageHandler handler_;
  std::string last_event_json_;
};

#endif

} // namespace

exv::ui_shell::WindowBounds webview2_default_window_bounds() noexcept {
  return exv::ui_shell::kElectronAdvancedWindowBounds;
}

exv::ui_shell::WindowBounds
webview2_window_mode_bounds_for_dpi(std::string_view mode,
                                    unsigned int dpi) noexcept {
  const auto bounds = mode == "minimal"
                          ? exv::ui_shell::kElectronMinimalWindowBounds
                          : exv::ui_shell::kElectronAdvancedWindowBounds;
  const int effective_dpi =
      dpi == 0 ? static_cast<int>(kDefaultDpi) : static_cast<int>(dpi);
  return {MulDiv(bounds.width, effective_dpi, static_cast<int>(kDefaultDpi)),
          MulDiv(bounds.height, effective_dpi, static_cast<int>(kDefaultDpi))};
}

bool webview2_should_create_tray_on_start() {
  return true;
}

WebView2CloseDecision webview2_close_decision_for_connection(
    bool vpn_connected, bool has_remembered_preference) noexcept {
  (void)vpn_connected;
  if (has_remembered_preference) {
    return WebView2CloseDecision::ApplyRememberedPreference;
  }
  return WebView2CloseDecision::Prompt;
}

int webview2_app_icon_resource_id() noexcept {
  return IDI_EXV_APP;
}

std::wstring webview2_taskbar_created_message_name() {
  return L"TaskbarCreated";
}

std::vector<WebView2TrayMenuItem>
webview2_tray_menu_model(const exv::ui_shell::TrayStatusSnapshot &snapshot) {
  std::vector<WebView2TrayMenuItem> items;
  if (!snapshot.connected) {
    items.push_back({L"显示主界面", kTrayCommandShow, false, true});
    items.push_back({L"退出", kTrayCommandQuit, false, true});
    return items;
  }
  for (const auto &label : exv::ui_shell::tray_status_snapshot_menu_labels(
           snapshot)) {
    items.push_back({wide_from_utf8(label), 0, false, false});
  }
  items.push_back({L"", 0, true, false});
  items.push_back({L"断开连接", kTrayCommandDisconnect, false,
                   snapshot.connected});
  items.push_back({L"显示主界面", kTrayCommandShow, false, true});
  items.push_back({L"", 0, true, false});
  items.push_back({L"退出", kTrayCommandQuit, false, true});
  return items;
}

std::wstring webview2_renderer_uri(
    const exv::ui_shell::RendererAssets &renderer) {
  if (renderer.kind == exv::ui_shell::RendererAssetKind::DevServer) {
    return wide_from_utf8(renderer.location);
  }

  std::filesystem::path path =
      std::filesystem::absolute(std::filesystem::path(renderer.location));
  std::wstring filename = path.filename().generic_wstring();
  const std::string encoded =
      percent_encode_file_uri_path(utf8_from_wide(filename.c_str()));
  if (encoded.empty()) {
    return {};
  }
  return wide_from_utf8(std::string("https://") + kPackagedRendererHost + "/" +
                        encoded);
}

std::wstring webview2_packaged_renderer_folder(
    const exv::ui_shell::RendererAssets &renderer) {
  if (renderer.kind == exv::ui_shell::RendererAssetKind::DevServer) {
    return {};
  }

  std::filesystem::path path =
      std::filesystem::absolute(std::filesystem::path(renderer.location));
  return path.parent_path().wstring();
}

std::string dispatch_webview2_host_message(
    const std::string &message_json,
    const exv::ui_shell::CoreRpcInvoker &invoke_core) {
  return exv::ui_shell::handle_host_request(message_json, invoke_core);
}

void post_webview2_host_response(
    const std::string &message_json,
    const exv::ui_shell::CoreRpcInvoker &invoke_core,
    const std::function<void(const std::string &)> &post_response) {
  post_response(dispatch_webview2_host_message(message_json, invoke_core));
}

std::unique_ptr<exv::ui_shell::UiWindow> create_webview2_window() {
  return std::make_unique<WebView2Window>();
}

} // namespace exv::platform::win32::ui_shell
