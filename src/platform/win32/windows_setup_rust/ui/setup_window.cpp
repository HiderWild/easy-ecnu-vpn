#include "windows_setup_rust/ui/setup_window.hpp"

#include "windows_setup_rust/cli.hpp"
#include "windows_setup_rust/elevate.hpp"
#include "windows_setup_rust/install_engine.hpp"
#include "windows_setup_rust/resource.hpp"
#include "windows_setup_rust/shortcuts.hpp"
#include "windows_setup_rust/uninstall_engine.hpp"
#include "windows_setup_rust/ui/icon_bitmaps.hpp"
#include "windows_setup_rust/ui/theme.hpp"

// Include D2D before windows.h pollution renames DrawText → DrawTextW/A.
#include <d2d1.h>
#include <dwrite.h>
#include <wincodec.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifdef DrawText
#undef DrawText
#endif
#ifdef DrawTextW
#undef DrawTextW
#endif
#ifdef DrawTextA
#undef DrawTextA
#endif
#include <windowsx.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <objbase.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace exv::setup::ui {
namespace {

enum class Page { Home, Progress, Finish, UninstallConfirm, UninstallProgress, Done, Error };

struct AppState {
  CliOptions options;
  Page page{Page::Home};
  bool uninstall{false};

  std::wstring install_dir;
  std::wstring status;
  std::wstring error;
  float display_progress{0.0f};
  float target_progress{0.0f};
  float wave_phase{0.0f};
  float card_opacity{1.0f};  // 1=home card, 0=pure progress transparency
  // Visual waterline 0..1 used for color/gray clip (independent of install % during intro).
  float visual_water{1.0f};
  float target_visual_water{1.0f};
  float icon_scale{1.0f};  // 1 at home, grows on install start
  bool intro_drain_active{false};
  bool deferred_work_started{false};
  // After engine completes: quickly fill water to 1.0 before Finish page.
  bool fill_water_before_finish{false};

  bool opt_desktop{true};
  bool opt_start_menu{true};
  bool opt_quick_launch{false};
  bool opt_launch{true};
  bool opt_clear_user_data{false};

  bool work_running{false};
  bool work_done{false};
  bool work_ok{false};

  // 停滞注入（P2）：引擎在某一步阻塞超过阈值时，水面仍**小幅蠕动**（安装上涨/卸载下降），
  // 避免用户感觉「卡住」——但只在最后一次真实进度 `stall_base` 之上/之下最多 4% 内蠕动，
  // 到达即停，绝不虚高误导（此前无界累加导致「关旧实例就推到 100%」）。
  double last_engine_update_ms{0.0};
  float stall_base{0.0f};   // 最后一次引擎真实进度的水面基准
  float stall_water{0.0f};  // 注入后的目标水面（= stall_base ± 最多 4%）

  HWND hwnd{nullptr};
  UINT dpi{96};
  ID2D1Factory *d2d{nullptr};
  IDWriteFactory *dwrite{nullptr};
  IWICImagingFactory *wic{nullptr};
  ID2D1HwndRenderTarget *hwnd_rt{nullptr};
  ID2D1DCRenderTarget *dc_rt{nullptr};
  IDWriteTextFormat *title_tf{nullptr};
  IDWriteTextFormat *body_tf{nullptr};
  IDWriteTextFormat *button_tf{nullptr};
  ID2D1Bitmap *icon_color{nullptr};
  ID2D1Bitmap *icon_gray{nullptr};
  bool icon_loaded{false};

  ProgressModel progress_model;
  std::thread worker;

  // Hit targets rebuilt each paint (DIP coords, design space @ 96 DPI).
  D2D1_RECT_F content_rect{};
  D2D1_RECT_F hit_install{};
  D2D1_RECT_F hit_browse{};
  D2D1_RECT_F hit_path_field{};
  D2D1_RECT_F hit_finish{};
  D2D1_RECT_F hit_uninstall{};
  D2D1_RECT_F hit_close{};
  D2D1_RECT_F hit_check_desktop{};
  D2D1_RECT_F hit_check_start{};
  D2D1_RECT_F hit_check_quick{};
  D2D1_RECT_F hit_check_launch{};
  D2D1_RECT_F hit_check_clear{};
  D2D1_RECT_F hit_window_close{};  // top-right chrome close

  // Pointer / hover (DIPs). Hover amounts are 0..1, animated toward hot targets (no layout shift).
  float pointer_x{-1.0f};
  float pointer_y{-1.0f};
  bool pointer_inside{false};
  bool path_truncated{false};
  float hover_install{0.0f};
  float hover_browse{0.0f};
  float hover_finish{0.0f};
  float hover_uninstall{0.0f};
  float hover_close{0.0f};
  float hover_window_close{0.0f};
  float hover_path{0.0f};
  float hover_check_desktop{0.0f};
  float hover_check_start{0.0f};
  float hover_check_quick{0.0f};
  float hover_check_launch{0.0f};
  float hover_check_clear{0.0f};
  bool hand_cursor{false};
  // Tooltips appear only after sustained hover (~500ms).
  float path_hover_hold_s{0.0f};
  float path_tooltip_alpha{0.0f};
  float browse_hover_hold_s{0.0f};
  float browse_tooltip_alpha{0.0f};
  float close_hover_hold_s{0.0f};
  float close_tooltip_alpha{0.0f};

  // Install path validity (home page).
  bool install_dir_valid{true};
  std::wstring install_dir_error;

  // Splash droplets that leap above the waterline and fall back under.
  struct Droplet {
    float x{0};
    float y{0};
    float vx{0};
    float vy{0};
    float peak_y{0};      // lowest Y (highest on screen) — for debug/limits
    float surface_y{0};   // waterline Y when spawned
    float radius{0};
    bool alive{false};
  };
  static constexpr int kMaxDroplets = 10;
  Droplet droplets[kMaxDroplets]{};
  float droplet_spawn_cooldown{0.8f};
};

AppState *g_app = nullptr;

constexpr UINT kDefaultDpi = 96;

using GetDpiForWindowFn = UINT(WINAPI *)(HWND);
using GetDpiForSystemFn = UINT(WINAPI *)();
using SetProcessDpiAwarenessContextFn = BOOL(WINAPI *)(void *);

FARPROC User32Proc(const char *name) {
  HMODULE user32 = GetModuleHandleW(L"user32.dll");
  return user32 ? GetProcAddress(user32, name) : nullptr;
}

void EnableProcessDpiAwareness() {
  // Prefer Per-Monitor V2 (Win10 1703+). Manifest also declares this; runtime call is belt-and-suspenders.
#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((void *)(intptr_t) - 4)
#endif
  auto *set_ctx = reinterpret_cast<SetProcessDpiAwarenessContextFn>(
      User32Proc("SetProcessDpiAwarenessContext"));
  if (set_ctx && set_ctx(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {
    return;
  }
  // Fallback: system DPI aware (Vista+).
  HMODULE shcore = LoadLibraryW(L"Shcore.dll");
  if (shcore) {
    using SetProcessDpiAwarenessFn = HRESULT(WINAPI *)(int);
    auto *set_awareness =
        reinterpret_cast<SetProcessDpiAwarenessFn>(GetProcAddress(shcore, "SetProcessDpiAwareness"));
    // PROCESS_PER_MONITOR_DPI_AWARE = 2
    if (set_awareness) {
      set_awareness(2);
    }
    FreeLibrary(shcore);
  } else {
    SetProcessDPIAware();
  }
}

UINT QuerySystemDpi() {
  auto *get_sys = reinterpret_cast<GetDpiForSystemFn>(User32Proc("GetDpiForSystem"));
  if (get_sys) {
    const UINT dpi = get_sys();
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

UINT QueryWindowDpi(HWND hwnd) {
  auto *get_win = reinterpret_cast<GetDpiForWindowFn>(User32Proc("GetDpiForWindow"));
  if (get_win && hwnd) {
    const UINT dpi = get_win(hwnd);
    if (dpi != 0) {
      return dpi;
    }
  }
  return QuerySystemDpi();
}

int ScalePx(int value, UINT dpi) {
  return MulDiv(value, static_cast<int>(dpi), static_cast<int>(kDefaultDpi));
}

float PixelsToDips(float px, UINT dpi) {
  return px * static_cast<float>(kDefaultDpi) / static_cast<float>(dpi);
}

float DipsToPixels(float dip, UINT dpi) {
  return dip * static_cast<float>(dpi) / static_cast<float>(kDefaultDpi);
}

float Lerp(float a, float b, float t) {
  return a + (b - a) * std::clamp(t, 0.0f, 1.0f);
}

bool Hit(float x, float y, const D2D1_RECT_F &r) {
  return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
}

D2D1_RECT_F ButtonRect(float cx, float y, float w = 180.0f, float h = 42.0f) {
  return D2D1::RectF(cx - w * 0.5f, y, cx + w * 0.5f, y + h);
}

void DrawD2DText(ID2D1RenderTarget *rt, IDWriteTextFormat *tf, ID2D1Brush *brush,
                 const std::wstring &text, D2D1_RECT_F rect,
                 std::optional<DWRITE_TEXT_ALIGNMENT> align_override = std::nullopt) {
  if (rt == nullptr || tf == nullptr || brush == nullptr || g_app == nullptr ||
      g_app->dwrite == nullptr) {
    return;
  }
  // Use DrawTextLayout to avoid winuser.h DrawText macro renaming the D2D method.
  IDWriteTextLayout *layout = nullptr;
  const float w = rect.right - rect.left;
  const float h = rect.bottom - rect.top;
  if (FAILED(g_app->dwrite->CreateTextLayout(text.c_str(), static_cast<UINT32>(text.size()), tf,
                                             w, h, &layout)) ||
      layout == nullptr) {
    return;
  }
  // CreateTextLayout already inherits title_tf/button_tf CENTER (or body LEADING).
  // Only override when the caller explicitly requests a different alignment —
  // forcing LEADING here previously left-shifted button and title labels.
  if (align_override.has_value()) {
    layout->SetTextAlignment(*align_override);
  }
  rt->DrawTextLayout(D2D1::Point2F(rect.left, rect.top), layout, brush);
  layout->Release();
}

void ReleaseTextFormats(AppState *app) {
  if (app->title_tf) {
    app->title_tf->Release();
    app->title_tf = nullptr;
  }
  if (app->body_tf) {
    app->body_tf->Release();
    app->body_tf = nullptr;
  }
  if (app->button_tf) {
    app->button_tf->Release();
    app->button_tf = nullptr;
  }
}

void EnsureTextFormats(AppState *app) {
  if (app->title_tf != nullptr) {
    return;
  }
  // Font sizes are in DIPs (design px @ 96 DPI). D2D DIP mode scales them with DPI.
  auto create_tf = [&](float size, DWRITE_FONT_WEIGHT weight, IDWriteTextFormat **out) {
    if (FAILED(app->dwrite->CreateTextFormat(kFontFamily, nullptr, weight, DWRITE_FONT_STYLE_NORMAL,
                                             DWRITE_FONT_STRETCH_NORMAL, size, L"zh-cn", out)) ||
        *out == nullptr) {
      app->dwrite->CreateTextFormat(kFontFamilyFallback, nullptr, weight, DWRITE_FONT_STYLE_NORMAL,
                                    DWRITE_FONT_STRETCH_NORMAL, size, L"en-us", out);
    }
  };

  create_tf(40.0f, DWRITE_FONT_WEIGHT_BOLD, &app->title_tf);
  if (app->title_tf) {
    app->title_tf->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
    app->title_tf->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
  }

  create_tf(13.5f, DWRITE_FONT_WEIGHT_NORMAL, &app->body_tf);
  create_tf(16.0f, DWRITE_FONT_WEIGHT_SEMI_BOLD, &app->button_tf);
  if (app->button_tf) {
    app->button_tf->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_CENTER);
    app->button_tf->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
  }
}

bool IsProgressPage(Page p) {
  return p == Page::Progress || p == Page::UninstallProgress;
}

float WaterLevel(const AppState *app) {
  // Driven by visual_water (intro drain + install rise / uninstall fall).
  return std::clamp(app->visual_water, 0.0f, 1.0f);
}

bool IsInteractiveControl(const AppState *app, float x, float y) {
  if (Hit(x, y, app->hit_install) || Hit(x, y, app->hit_browse) || Hit(x, y, app->hit_path_field) ||
      Hit(x, y, app->hit_finish) || Hit(x, y, app->hit_uninstall) || Hit(x, y, app->hit_close) ||
      Hit(x, y, app->hit_window_close) || Hit(x, y, app->hit_check_desktop) ||
      Hit(x, y, app->hit_check_start) || Hit(x, y, app->hit_check_quick) ||
      Hit(x, y, app->hit_check_launch) || Hit(x, y, app->hit_check_clear)) {
    return true;
  }
  return false;
}

bool IsHandCursorControl(const AppState *app, float x, float y) {
  // Path field keeps arrow (it's a value surface); buttons/checkboxes use hand.
  // Disabled install button stays arrow.
  if (Hit(x, y, app->hit_install)) {
    return app->install_dir_valid;
  }
  return Hit(x, y, app->hit_browse) || Hit(x, y, app->hit_finish) ||
         Hit(x, y, app->hit_uninstall) || Hit(x, y, app->hit_close) ||
         Hit(x, y, app->hit_window_close) || Hit(x, y, app->hit_check_desktop) ||
         Hit(x, y, app->hit_check_start) || Hit(x, y, app->hit_check_quick) ||
         Hit(x, y, app->hit_check_launch) || Hit(x, y, app->hit_check_clear);
}

void ApplyCursor(AppState *app) {
  if (app == nullptr) {
    return;
  }
  const bool want_hand =
      app->pointer_inside && IsHandCursorControl(app, app->pointer_x, app->pointer_y);
  if (want_hand == app->hand_cursor) {
    // Still re-assert every move so nested HitTest/capture doesn't stick the arrow.
    SetCursor(LoadCursor(nullptr, want_hand ? IDC_HAND : IDC_ARROW));
    return;
  }
  app->hand_cursor = want_hand;
  SetCursor(LoadCursor(nullptr, want_hand ? IDC_HAND : IDC_ARROW));
}

void DrawEllipsisText(ID2D1RenderTarget *rt, IDWriteFactory *dwrite, IDWriteTextFormat *tf,
                      ID2D1Brush *brush, const std::wstring &text, D2D1_RECT_F rect,
                      bool *out_truncated) {
  if (out_truncated) {
    *out_truncated = false;
  }
  if (rt == nullptr || dwrite == nullptr || tf == nullptr || brush == nullptr) {
    return;
  }
  IDWriteTextLayout *layout = nullptr;
  const float w = std::max(1.0f, rect.right - rect.left);
  const float h = std::max(1.0f, rect.bottom - rect.top);
  if (FAILED(dwrite->CreateTextLayout(text.c_str(), static_cast<UINT32>(text.size()), tf, w, h,
                                      &layout)) ||
      layout == nullptr) {
    return;
  }
  layout->SetWordWrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
  layout->SetMaxWidth(w);
  layout->SetMaxHeight(h);
  // Trimming with ellipsis character.
  IDWriteInlineObject *trimming_sign = nullptr;
  dwrite->CreateEllipsisTrimmingSign(tf, &trimming_sign);
  DWRITE_TRIMMING trim{};
  trim.granularity = DWRITE_TRIMMING_GRANULARITY_CHARACTER;
  layout->SetTrimming(&trim, trimming_sign);
  if (trimming_sign) {
    trimming_sign->Release();
  }
  layout->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
  layout->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);

  DWRITE_TEXT_METRICS metrics{};
  if (SUCCEEDED(layout->GetMetrics(&metrics)) && out_truncated) {
    *out_truncated = metrics.widthIncludingTrailingWhitespace > w + 0.5f || metrics.lineCount > 1;
    // Also detect max-width overflow via trimming by measuring unconstrained.
    IDWriteTextLayout *full = nullptr;
    if (SUCCEEDED(dwrite->CreateTextLayout(text.c_str(), static_cast<UINT32>(text.size()), tf,
                                           100000.0f, h, &full)) &&
        full != nullptr) {
      DWRITE_TEXT_METRICS full_m{};
      if (SUCCEEDED(full->GetMetrics(&full_m))) {
        *out_truncated = full_m.widthIncludingTrailingWhitespace > w + 0.5f;
      }
      full->Release();
    }
  }
  rt->DrawTextLayout(D2D1::Point2F(rect.left, rect.top), layout, brush);
  layout->Release();
}

void DrawPrimaryButton(ID2D1RenderTarget *rt, IDWriteTextFormat *tf, const D2D1_RECT_F &rect,
                       const std::wstring &label, float hover, float brand_r, float brand_g,
                       float brand_b, bool enabled = true) {
  // Flat solid fill only. Disabled = muted gray, no hover lift.
  const float h = enabled ? std::clamp(hover, 0.0f, 1.0f) : 0.0f;
  float r = 0.62f, g = 0.62f, b = 0.65f;
  if (enabled) {
    const float lift = 0.08f * h;
    r = std::min(1.0f, brand_r + (1.0f - brand_r) * lift);
    g = std::min(1.0f, brand_g + (1.0f - brand_g) * lift);
    b = std::min(1.0f, brand_b + (1.0f - brand_b) * lift);
  }

  ID2D1SolidColorBrush *fill = nullptr;
  ID2D1SolidColorBrush *label_brush = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(r, g, b, enabled ? 1.0f : 0.85f), &fill);
  rt->CreateSolidColorBrush(D2D1::ColorF(1, 1, 1, enabled ? 1.0f : 0.75f), &label_brush);
  if (fill) {
    rt->FillRoundedRectangle(D2D1::RoundedRect(rect, 12, 12), fill);
    fill->Release();
  }
  if (label_brush) {
    DrawD2DText(rt, tf, label_brush, label, rect);
    label_brush->Release();
  }
}

void DrawSecondaryButton(ID2D1RenderTarget *rt, IDWriteTextFormat *tf, const D2D1_RECT_F &rect,
                         const std::wstring &label, float hover, float brand_r, float brand_g,
                         float brand_b) {
  // Flat solid only — matches primary style.
  const float h = std::clamp(hover, 0.0f, 1.0f);
  const float lift = 0.10f * h;
  const float r = std::min(1.0f, brand_r + (1.0f - brand_r) * lift);
  const float g = std::min(1.0f, brand_g + (1.0f - brand_g) * lift);
  const float b = std::min(1.0f, brand_b + (1.0f - brand_b) * lift);

  ID2D1SolidColorBrush *fill = nullptr;
  ID2D1SolidColorBrush *label_brush = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(r, g, b, 1.0f), &fill);
  rt->CreateSolidColorBrush(D2D1::ColorF(1, 1, 1, 1), &label_brush);
  if (fill) {
    rt->FillRoundedRectangle(D2D1::RoundedRect(rect, 8, 8), fill);
    fill->Release();
  }
  if (label_brush) {
    DrawD2DText(rt, tf, label_brush, label, rect);
    label_brush->Release();
  }
}

void DrawPathField(ID2D1RenderTarget *rt, IDWriteFactory *dwrite, IDWriteTextFormat *tf,
                   const D2D1_RECT_F &rect, const std::wstring &path, float hover,
                   bool *out_truncated) {
  const float h = std::clamp(hover, 0.0f, 1.0f);
  ID2D1SolidColorBrush *field = nullptr;
  ID2D1SolidColorBrush *edge = nullptr;
  ID2D1SolidColorBrush *text = nullptr;
  // Slight brighten + stronger edge on hover — no move.
  rt->CreateSolidColorBrush(D2D1::ColorF(0.96f + 0.02f * h, 0.96f + 0.02f * h, 0.975f + 0.02f * h, 1),
                            &field);
  rt->CreateSolidColorBrush(D2D1::ColorF(0, 0, 0, 0.06f + 0.06f * h), &edge);
  rt->CreateSolidColorBrush(D2D1::ColorF(0.16f, 0.16f, 0.19f, 1), &text);
  if (field) {
    rt->FillRoundedRectangle(D2D1::RoundedRect(rect, 8, 8), field);
    field->Release();
  }
  if (edge) {
    rt->DrawRoundedRectangle(D2D1::RoundedRect(rect, 8, 8), edge, 1.0f);
    edge->Release();
  }
  if (text) {
    const D2D1_RECT_F text_rect =
        D2D1::RectF(rect.left + 10.0f, rect.top + 2.0f, rect.right - 8.0f, rect.bottom - 2.0f);
    DrawEllipsisText(rt, dwrite, tf, text, path, text_rect, out_truncated);
    text->Release();
  }
}

// place: 0 = below anchor, 1 = above anchor, 2 = left of anchor, 3 = right of anchor.
void DrawTooltip(ID2D1RenderTarget *rt, IDWriteFactory *dwrite, IDWriteTextFormat *tf,
                 const D2D1_RECT_F &anchor, const std::wstring &text, float appear, int place = 0) {
  if (appear < 0.02f || text.empty() || dwrite == nullptr || tf == nullptr) {
    return;
  }
  const float a = std::clamp(appear, 0.0f, 1.0f);
  const float max_w = 320.0f;
  IDWriteTextLayout *layout = nullptr;
  if (FAILED(dwrite->CreateTextLayout(text.c_str(), static_cast<UINT32>(text.size()), tf, max_w,
                                      200.0f, &layout)) ||
      layout == nullptr) {
    return;
  }
  layout->SetWordWrapping(DWRITE_WORD_WRAPPING_WRAP);
  DWRITE_TEXT_METRICS metrics{};
  layout->GetMetrics(&metrics);
  const float pad_x = 10.0f;
  const float pad_y = 8.0f;
  const float tw = std::min(max_w, metrics.widthIncludingTrailingWhitespace) + pad_x * 2.0f;
  const float th = metrics.height + pad_y * 2.0f;

  float left = anchor.left;
  float top = anchor.bottom + 8.0f;
  if (place == 1) {
    left = anchor.left;
    top = anchor.top - th - 8.0f;
  } else if (place == 2) {
    left = anchor.left - tw - 8.0f;
    top = anchor.top + (anchor.bottom - anchor.top - th) * 0.5f;
  } else if (place == 3) {
    left = anchor.right + 8.0f;
    top = anchor.top + (anchor.bottom - anchor.top - th) * 0.5f;
  }
  const D2D1_RECT_F box = D2D1::RectF(left, top, left + tw, top + th);

  ID2D1SolidColorBrush *bg = nullptr;
  ID2D1SolidColorBrush *edge = nullptr;
  ID2D1SolidColorBrush *fg = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(0.12f, 0.12f, 0.14f, 0.92f * a), &bg);
  rt->CreateSolidColorBrush(D2D1::ColorF(1, 1, 1, 0.10f * a), &edge);
  rt->CreateSolidColorBrush(D2D1::ColorF(1, 1, 1, 0.95f * a), &fg);
  for (float expand : {5.0f, 2.5f}) {
    ID2D1SolidColorBrush *sh = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(0, 0, 0, 0.10f * a), &sh);
    if (sh) {
      rt->FillRoundedRectangle(
          D2D1::RoundedRect(D2D1::RectF(box.left - expand * 0.2f, box.top + 1.0f + expand * 0.15f,
                                        box.right + expand * 0.2f, box.bottom + expand * 0.35f),
                            8, 8),
          sh);
      sh->Release();
    }
  }
  if (bg) {
    rt->FillRoundedRectangle(D2D1::RoundedRect(box, 8, 8), bg);
    bg->Release();
  }
  if (edge) {
    rt->DrawRoundedRectangle(D2D1::RoundedRect(box, 8, 8), edge, 1.0f);
    edge->Release();
  }
  if (fg) {
    rt->DrawTextLayout(D2D1::Point2F(box.left + pad_x, box.top + pad_y), layout, fg);
    fg->Release();
  }
  layout->Release();
}

void DrawPathTooltip(ID2D1RenderTarget *rt, IDWriteFactory *dwrite, IDWriteTextFormat *tf,
                     const D2D1_RECT_F &anchor, const std::wstring &path, float appear) {
  DrawTooltip(rt, dwrite, tf, anchor, path, appear, 0);
}

bool IsInstallDirValid(const std::wstring &path, std::wstring *error_out) {
  auto fail = [&](const wchar_t *msg) {
    if (error_out) {
      *error_out = msg;
    }
    return false;
  };
  if (path.empty()) {
    return fail(L"请指定安装目录");
  }
  // Reject obvious invalid / relative junk.
  if (path.find(L"<>\"|?*") != std::wstring::npos) {
    return fail(L"安装目录包含非法字符");
  }
  for (wchar_t ch : path) {
    if (ch < 32) {
      return fail(L"安装目录包含非法控制字符");
    }
    if (ch == L'<' || ch == L'>' || ch == L'"' || ch == L'|' || ch == L'?' || ch == L'*') {
      return fail(L"安装目录包含非法字符");
    }
  }
  // Require absolute path with drive or UNC.
  const bool unc = path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\';
  const bool drive = path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') ||
                                          (path[0] >= L'a' && path[0] <= L'z')) &&
                     path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
  if (!unc && !drive) {
    return fail(L"请使用绝对路径（例如 C:\\Program Files\\EXV）");
  }
  if (!CanWriteDirectory(path)) {
    return fail(L"目录不可写或无法创建，请换一个有权限的位置");
  }
  if (error_out) {
    error_out->clear();
  }
  return true;
}

void RefreshInstallDirValidity(AppState *app) {
  if (app == nullptr) {
    return;
  }
  std::wstring err;
  app->install_dir_valid = IsInstallDirValid(app->install_dir, &err);
  app->install_dir_error = err;
}

void EnsureIcon(AppState *app, ID2D1RenderTarget *rt) {
  if (app->icon_loaded || rt == nullptr || app->wic == nullptr) {
    return;
  }
  app->icon_loaded = true;
  LoadIconLayers(rt, app->wic, &app->icon_color, &app->icon_gray);
}

struct WaveLayerParams {
  float base_offset;  // vertical offset from mean waterline (px, positive = lower)
  float amp;
  float cycles;
  float speed;
  float phase0;
  float r, g, b, a;  // solid fill color of everything BELOW this wave surface
};

float SampleWaveY(float mean_y, float t, float phase, const WaveLayerParams &p) {
  return mean_y + p.base_offset +
         std::sin(t * 6.283185f * p.cycles + phase * p.speed + p.phase0) * p.amp +
         std::sin(t * 6.283185f * (p.cycles * 0.47f) + phase * p.speed * 1.3f + p.phase0 * 0.7f) *
             (p.amp * 0.32f);
}

// Filled region: wave surface as the TOP edge, solid down to bounds.bottom.
// This is a water BODY, not "area under a sine vs the x-axis".
ID2D1PathGeometry *CreateWaveBodyGeometry(AppState *app, D2D1_RECT_F bounds, float mean_water_y,
                                          float phase, const WaveLayerParams &p) {
  ID2D1PathGeometry *geo = nullptr;
  if (FAILED(app->d2d->CreatePathGeometry(&geo)) || geo == nullptr) {
    return nullptr;
  }
  ID2D1GeometrySink *sink = nullptr;
  if (FAILED(geo->Open(&sink)) || sink == nullptr) {
    geo->Release();
    return nullptr;
  }
  const float left = bounds.left - 1.0f;
  const float right = bounds.right + 1.0f;
  const float bottom = bounds.bottom + 1.0f;
  const int steps = 64;
  // Start at bottom-left, go up to left surface point, along wave, down to bottom-right, close.
  const float y0 = SampleWaveY(mean_water_y, 0.0f, phase, p);
  sink->BeginFigure(D2D1::Point2F(left, bottom), D2D1_FIGURE_BEGIN_FILLED);
  sink->AddLine(D2D1::Point2F(left, y0));
  for (int i = 1; i <= steps; ++i) {
    const float t = static_cast<float>(i) / steps;
    const float x = left + (right - left) * t;
    sink->AddLine(D2D1::Point2F(x, SampleWaveY(mean_water_y, t, phase, p)));
  }
  sink->AddLine(D2D1::Point2F(right, bottom));
  sink->EndFigure(D2D1_FIGURE_END_CLOSED);
  sink->Close();
  sink->Release();
  return geo;
}

void DrawDroplets(AppState *app, ID2D1RenderTarget *rt, D2D1_RECT_F stage, float mean_water_y) {
  for (int i = 0; i < AppState::kMaxDroplets; ++i) {
    auto &d = app->droplets[i];
    if (!d.alive) {
      continue;
    }
    // Visible while airborne and while briefly plunging back under the surface.
    float a = 0.72f;
    if (d.y > mean_water_y) {
      // Fade quickly once submerged so they "disappear into the pool".
      a *= std::clamp(1.0f - (d.y - mean_water_y) / 12.0f, 0.0f, 1.0f);
    }
    if (a < 0.02f) {
      continue;
    }
    ID2D1SolidColorBrush *b = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(kBrandR * 0.95f, kBrandG * 0.88f, kBrandB * 0.92f, a), &b);
    if (b) {
      rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(d.x, d.y), d.radius, d.radius * 1.05f), b);
      b->Release();
    }
  }
  (void)stage;
}

void UpdateDroplets(AppState *app, D2D1_RECT_F stage, float mean_water_y, float dt) {
  const float pool_h = std::max(1.0f, stage.bottom - stage.top);
  // Apex of trajectory must stay within 10% of pool height above the waterline.
  const float max_apex = pool_h * 0.10f;
  // g chosen so a typical hop falls back visibly (not frozen at apex).
  const float gravity = 520.0f;  // DIPs/s^2

  for (int i = 0; i < AppState::kMaxDroplets; ++i) {
    auto &d = app->droplets[i];
    if (!d.alive) {
      continue;
    }
    d.vy += gravity * dt;
    d.x += d.vx * dt;
    d.y += d.vy * dt;
    if (d.y < d.peak_y) {
      d.peak_y = d.y;
    }
    // Soft clamp: never let apex exceed 10% pool height.
    const float min_y = d.surface_y - max_apex;
    if (d.y < min_y) {
      d.y = min_y;
      if (d.vy < 0.0f) {
        d.vy = 0.0f;  // start falling immediately if overshot
      }
    }
    // Absorb once clearly under the surface after having gone up and come down.
    const bool submerged = d.y >= mean_water_y + 6.0f && d.vy > 0.0f;
    const bool out_of_pool = d.x < stage.left - 4.0f || d.x > stage.right + 4.0f;
    if (submerged || out_of_pool) {
      d.alive = false;
    }
  }

  app->droplet_spawn_cooldown -= dt;
  if (app->droplet_spawn_cooldown > 0.0f) {
    return;
  }

  // Occasional, slow spawns — not every frame.
  for (int i = 0; i < AppState::kMaxDroplets; ++i) {
    if (app->droplets[i].alive) {
      continue;
    }
    auto &d = app->droplets[i];
    d.alive = true;
    // Random-ish but stable-ish distribution along crest.
    const float t = 0.18f + 0.64f * (static_cast<float>((GetTickCount() * 17 + i * 97) % 1000) /
                                     1000.0f);
    d.x = stage.left + (stage.right - stage.left) * t;
    d.surface_y = mean_water_y;
    d.y = mean_water_y - 1.0f;
    d.peak_y = d.y;
    // Small diagonal hop. Limit upward speed so apex ~ 4%..10% of pool height:
    // h = v^2 / (2g)  =>  v = sqrt(2 g h)
    const float apex_frac = 0.04f + 0.06f * (static_cast<float>((GetTickCount() + i * 13) % 100) /
                                             100.0f);
    const float apex = pool_h * apex_frac;
    const float v_up = std::sqrt(2.0f * gravity * apex);
    const float side = ((GetTickCount() + i) & 1) ? 1.0f : -1.0f;
    d.vx = side * (18.0f + static_cast<float>((GetTickCount() + i * 7) % 22));  // mild sideways
    d.vy = -v_up;
    // Bounded random size — small beads, not blobs (DIPs).
    // Range ~1.2 .. 2.6 so they read as droplets, not coins.
    {
      const unsigned seed = static_cast<unsigned>(GetTickCount() + i * 37u + 11u);
      const float u = static_cast<float>(seed % 1000) / 1000.0f;
      d.radius = 1.2f + u * 1.4f;
    }
    app->droplet_spawn_cooldown = 0.85f + static_cast<float>((GetTickCount() + i) % 40) * 0.02f;
    break;
  }
  if (app->droplet_spawn_cooldown <= 0.0f) {
    app->droplet_spawn_cooldown = 0.6f;
  }
}

void DrawStageWaveFill(AppState *app, ID2D1RenderTarget *rt, D2D1_RECT_F stage, float water01) {
  // Three water bodies. Wave surface = TOP boundary of a solid body that extends to stage.bottom.
  // Fill uses a vertical gradient: brand-tinted at the surface → white at the pool floor (no hard edge).
  // Cap the surface below stage.top so we never flood the entire stage into a solid red rectangle.
  const float water = std::clamp(water01, 0.0f, 0.88f);
  if (water <= 0.001f) {
    return;
  }
  // Extra top headroom so crests keep distance from the stage ceiling / card top.
  const float usable_top = stage.top + 6.0f;
  const float usable_h = std::max(1.0f, stage.bottom - usable_top);
  const float mean_y = stage.bottom - usable_h * water;
  const float phase = app->wave_phase;

  // Back → front: different period / speed / depth; surface stays chromatic, floor fades to white.
  const WaveLayerParams layers[3] = {
      {-3.5f, 9.5f, 1.05f, 0.55f, 0.4f, kBrandR * 0.78f, kBrandG * 0.58f, kBrandB * 0.66f, 0.72f},
      {0.0f, 7.0f, 1.55f, 0.95f, 1.7f, kBrandR * 0.90f, kBrandG * 0.74f, kBrandB * 0.80f, 0.78f},
      {2.0f, 4.8f, 2.15f, 1.35f, 2.9f, kBrandR, kBrandG, kBrandB, 0.88f},
  };

  for (const auto &layer : layers) {
    ID2D1PathGeometry *body = CreateWaveBodyGeometry(app, stage, mean_y, phase, layer);
    if (!body) {
      continue;
    }

    ID2D1GradientStopCollection *stops = nullptr;
    D2D1_GRADIENT_STOP gs[3]{};
    // Surface (top of water body)
    gs[0].position = 0.0f;
    gs[0].color = D2D1::ColorF(layer.r, layer.g, layer.b, layer.a);
    // Mid blend
    gs[1].position = 0.55f;
    gs[1].color = D2D1::ColorF(std::min(1.0f, layer.r * 0.45f + 0.55f),
                                std::min(1.0f, layer.g * 0.45f + 0.55f),
                                std::min(1.0f, layer.b * 0.45f + 0.55f), layer.a * 0.55f);
    // Floor → white / fully clear into the card
    gs[2].position = 1.0f;
    gs[2].color = D2D1::ColorF(1.0f, 1.0f, 1.0f, 0.0f);

    if (SUCCEEDED(rt->CreateGradientStopCollection(gs, 3, D2D1_GAMMA_2_2,
                                                   D2D1_EXTEND_MODE_CLAMP, &stops)) &&
        stops != nullptr) {
      ID2D1LinearGradientBrush *grad = nullptr;
      // Gradient axis is vertical from mean surface down to the stage floor.
      const D2D1_LINEAR_GRADIENT_BRUSH_PROPERTIES props =
          D2D1::LinearGradientBrushProperties(D2D1::Point2F(stage.left, mean_y + layer.base_offset),
                                              D2D1::Point2F(stage.left, stage.bottom));
      if (SUCCEEDED(rt->CreateLinearGradientBrush(props, stops, &grad)) && grad != nullptr) {
        rt->FillGeometry(body, grad);
        grad->Release();
      }
      stops->Release();
    } else {
      ID2D1SolidColorBrush *fill = nullptr;
      rt->CreateSolidColorBrush(D2D1::ColorF(layer.r, layer.g, layer.b, layer.a * 0.65f), &fill);
      if (fill) {
        rt->FillGeometry(body, fill);
        fill->Release();
      }
    }
    body->Release();
  }

  // Bright thin crest for the front wave only (surface line).
  {
    const auto &front = layers[2];
    ID2D1SolidColorBrush *crest = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(1.0f, 1.0f, 1.0f, 0.32f), &crest);
    if (crest) {
      ID2D1PathGeometry *line = nullptr;
      if (SUCCEEDED(app->d2d->CreatePathGeometry(&line)) && line) {
        ID2D1GeometrySink *sink = nullptr;
        if (SUCCEEDED(line->Open(&sink)) && sink) {
          sink->BeginFigure(D2D1::Point2F(stage.left, SampleWaveY(mean_y, 0.0f, phase, front)),
                            D2D1_FIGURE_BEGIN_HOLLOW);
          const int steps = 64;
          for (int i = 1; i <= steps; ++i) {
            const float t = static_cast<float>(i) / steps;
            const float x = stage.left + (stage.right - stage.left) * t;
            sink->AddLine(D2D1::Point2F(x, SampleWaveY(mean_y, t, phase, front)));
          }
          sink->EndFigure(D2D1_FIGURE_END_OPEN);
          sink->Close();
          sink->Release();
          rt->DrawGeometry(line, crest, 1.5f);
        }
        line->Release();
      }
      crest->Release();
    }
  }

  DrawDroplets(app, rt, stage, mean_y);
}

void DrawWaveIcon(AppState *app, ID2D1RenderTarget *rt, float cx, float cy, float icon_size,
                  bool force_full_color) {
  EnsureIcon(app, rt);
  const float left = cx - icon_size * 0.5f;
  const float top = cy - icon_size * 0.5f;
  const float right = left + icon_size;
  const float bottom = top + icon_size;
  const float water = WaterLevel(app);
  // Once the glyph is fully filled it becomes a solid brand mark — no more
  // progress-wave clip that tracks the rectangular pool behind it.
  const bool solid_full =
      force_full_color || water >= 0.995f || app->page == Page::Finish;
  const float base_water_y = bottom - icon_size * water;
  const D2D1_RECT_F dest = D2D1::RectF(left, top, right, bottom);
  const D2D1_RECT_F icon_stage = dest;

  if (app->icon_gray && app->icon_color) {
    // Pre-install home / completed fill: entire icon brand-colored (no gray half).
    // In-progress install: gray above waterline, color below (wave = dye boundary).
    if (solid_full) {
      rt->DrawBitmap(app->icon_color, dest, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_LINEAR);
      return;
    }

    rt->DrawBitmap(app->icon_gray, dest, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_LINEAR);

    WaveLayerParams front{-0.5f, 5.0f, 2.15f, 1.35f, 2.9f, 1, 1, 1, 1};
    ID2D1PathGeometry *clip_geo =
        CreateWaveBodyGeometry(app, icon_stage, base_water_y, app->wave_phase, front);
    if (clip_geo) {
      ID2D1Layer *layer = nullptr;
      if (SUCCEEDED(rt->CreateLayer(nullptr, &layer)) && layer != nullptr) {
        rt->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), clip_geo), layer);
        rt->DrawBitmap(app->icon_color, dest, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_LINEAR);
        rt->PopLayer();
        layer->Release();
      } else {
        rt->PushAxisAlignedClip(D2D1::RectF(left, base_water_y, right, bottom),
                                D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        rt->DrawBitmap(app->icon_color, dest, 1.0f, D2D1_BITMAP_INTERPOLATION_MODE_LINEAR);
        rt->PopAxisAlignedClip();
      }
      clip_geo->Release();
    }
  } else {
    ID2D1SolidColorBrush *brand = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(kBrandR, kBrandG, kBrandB), &brand);
    const auto ellipse =
        D2D1::Ellipse(D2D1::Point2F(cx, cy), icon_size * 0.46f, icon_size * 0.46f);
    if (brand) {
      if (force_full_color) {
        rt->FillEllipse(ellipse, brand);
      } else {
        ID2D1SolidColorBrush *gray = nullptr;
        rt->CreateSolidColorBrush(D2D1::ColorF(0.62f, 0.62f, 0.65f), &gray);
        if (gray) {
          rt->FillEllipse(ellipse, gray);
          gray->Release();
        }
        rt->PushAxisAlignedClip(D2D1::RectF(left, base_water_y, right, bottom),
                                D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
        rt->FillEllipse(ellipse, brand);
        rt->PopAxisAlignedClip();
      }
      brand->Release();
    }
  }
}

void DrawWindowCloseButton(AppState *app, ID2D1RenderTarget *rt, D2D1_RECT_F card, float hover) {
  // Brand-red traffic-light style disc (no X glyph) — soft shadow + hover pulse.
  const float base = 12.0f;
  const float h = std::clamp(hover, 0.0f, 1.0f);
  const float radius = base * (1.0f + 0.08f * h);  // subtle grow, stays a "dot"
  const float margin = 14.0f;
  const float cx = card.right - margin - base;
  const float cy = card.top + margin + base;
  app->hit_window_close =
      D2D1::RectF(cx - base - 4.0f, cy - base - 4.0f, cx + base + 4.0f, cy + base + 4.0f);

  // Soft multi-ring shadow under the disc (no hard directional offset).
  for (float expand : {5.0f, 3.0f, 1.5f}) {
    ID2D1SolidColorBrush *sh = nullptr;
    const float a = (0.10f + 0.08f * h) * (expand < 2.0f ? 1.0f : 0.55f);
    rt->CreateSolidColorBrush(D2D1::ColorF(0, 0, 0, a), &sh);
    if (sh) {
      rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy + 0.6f), radius + expand * 0.55f,
                                    radius + expand * 0.55f),
                      sh);
      sh->Release();
    }
  }

  // Outer brand halo on hover (soft glow, same red family).
  if (h > 0.01f) {
    ID2D1SolidColorBrush *halo = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(kBrandR, kBrandG, kBrandB, 0.22f * h), &halo);
    if (halo) {
      rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), radius + 4.0f * h, radius + 4.0f * h),
                      halo);
      halo->Release();
    }
  }

  // Solid brand disc.
  const float lift = 0.10f * h;
  const float r = std::min(1.0f, kBrandR + (1.0f - kBrandR) * lift);
  const float g = std::min(1.0f, kBrandG + (1.0f - kBrandG) * lift);
  const float b = std::min(1.0f, kBrandB + (1.0f - kBrandB) * lift);
  ID2D1SolidColorBrush *fill = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(r, g, b, 1.0f), &fill);
  if (fill) {
    rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx, cy), radius, radius), fill);
    fill->Release();
  }

  // Specular highlight near top (tiny white crescent, not a two-tone split).
  ID2D1SolidColorBrush *hi = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(1, 1, 1, 0.22f + 0.18f * h), &hi);
  if (hi) {
    rt->FillEllipse(D2D1::Ellipse(D2D1::Point2F(cx - radius * 0.22f, cy - radius * 0.28f),
                                  radius * 0.28f, radius * 0.20f),
                    hi);
    hi->Release();
  }
}

void DrawCheckbox(ID2D1RenderTarget *rt, IDWriteFactory *dwrite, IDWriteTextFormat *body,
                  ID2D1SolidColorBrush *brand, ID2D1SolidColorBrush *dark, float x, float y, bool on,
                  const std::wstring &label, float col_right, D2D1_RECT_F *hit_out) {
  const auto box = D2D1::RectF(x, y, x + 18, y + 18);
  if (hit_out) {
    *hit_out = D2D1::RectF(x, y - 4, col_right, y + 24);
  }
  rt->DrawRectangle(box, brand, 1.6f);
  if (on) {
    rt->FillRectangle(D2D1::RectF(box.left + 3, box.top + 3, box.right - 3, box.bottom - 3), brand);
  }
  // Keep label left-aligned next to the box, but constrained to this column's right edge.
  const D2D1_RECT_F label_rect = D2D1::RectF(box.right + 10, y - 2, col_right, y + 22);
  if (dwrite != nullptr && body != nullptr) {
    bool trunc = false;
    DrawEllipsisText(rt, dwrite, body, dark, label, label_rect, &trunc);
    (void)trunc;
  } else {
    DrawD2DText(rt, body, dark, label, label_rect);
  }
}

void DrawSoftUniformShadow(ID2D1RenderTarget *rt, D2D1_RECT_F card, float radius, float opacity) {
  // Multi-ring outward glow — soft, small edge, even on all four sides (no directional offset).
  // Mimics the gentle OS chrome surround the main EXV window uses, not a hard drop shadow.
  struct Ring {
    float expand;
    float alpha;
  };
  const Ring rings[] = {
      {14.0f, 0.018f}, {11.0f, 0.028f}, {8.0f, 0.040f}, {5.5f, 0.055f},
      {3.5f, 0.070f},  {2.0f, 0.055f},  {1.0f, 0.035f},
  };
  for (const auto &ring : rings) {
    ID2D1SolidColorBrush *brush = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(0, 0, 0, ring.alpha * opacity), &brush);
    if (!brush) {
      continue;
    }
    const D2D1_RECT_F r = D2D1::RectF(card.left - ring.expand, card.top - ring.expand,
                                      card.right + ring.expand, card.bottom + ring.expand);
    const float rr = radius + ring.expand * 0.65f;
    rt->FillRoundedRectangle(D2D1::RoundedRect(r, rr, rr), brush);
    brush->Release();
  }
}

void DrawCardChrome(ID2D1RenderTarget *rt, D2D1_RECT_F card, float radius, float opacity) {
  DrawSoftUniformShadow(rt, card, radius, opacity);
  ID2D1SolidColorBrush *white = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(1, 1, 1, opacity), &white);
  if (white) {
    rt->FillRoundedRectangle(D2D1::RoundedRect(card, radius, radius), white);
    // Hairline edge like Aero/Win11 chrome.
    ID2D1SolidColorBrush *edge = nullptr;
    rt->CreateSolidColorBrush(D2D1::ColorF(0, 0, 0, 0.06f * opacity), &edge);
    if (edge) {
      rt->DrawRoundedRectangle(D2D1::RoundedRect(card, radius, radius), edge, 1.0f);
      edge->Release();
    }
    white->Release();
  }
}

void PaintScene(AppState *app, ID2D1RenderTarget *rt, float width, float height, bool /*transparent*/) {
  EnsureTextFormats(app);

  const float cx = width * 0.5f;
  // Finish uses progress scene only while the card is still fading in. Once the
  // card is fully opaque we settle on the rounded Finish layout (with buttons).
  const bool finish_settled =
      app->page == Page::Finish && app->card_opacity >= 0.98f;
  const bool progress_visual =
      IsProgressPage(app->page) || app->fill_water_before_finish ||
      (app->page == Page::Finish && !finish_settled);

  // Always clear to true transparent — card/shadow are the only opaque chrome.
  rt->Clear(D2D1::ColorF(0, 0, 0, 0));

  ID2D1SolidColorBrush *brand = nullptr;
  ID2D1SolidColorBrush *dark = nullptr;
  ID2D1SolidColorBrush *muted = nullptr;
  ID2D1SolidColorBrush *white = nullptr;
  rt->CreateSolidColorBrush(D2D1::ColorF(kBrandR, kBrandG, kBrandB), &brand);
  rt->CreateSolidColorBrush(D2D1::ColorF(0.16f, 0.16f, 0.19f), &dark);
  rt->CreateSolidColorBrush(D2D1::ColorF(0.45f, 0.45f, 0.50f), &muted);
  rt->CreateSolidColorBrush(D2D1::ColorF(D2D1::ColorF::White), &white);

  const float pad = kShadowMarginDip;
  const D2D1_RECT_F card = D2D1::RectF(pad, pad, width - pad, height - pad);
  app->content_rect = card;

  // Compact icon/wave stage: only the upper band. Title/form sit on clean white below.
  // Wave pool must NOT cover the EXV wordmark.
  // Leave headroom so the crest never hugs the rounded-rect top edge.
  const float stage_top = card.top + 28.0f;
  const float stage_bottom = card.top + 150.0f;
  // Flush to the card L/R edges — no white side gutters inside the pool.
  const D2D1_RECT_F icon_stage =
      D2D1::RectF(card.left, stage_top, card.right, stage_bottom);
  // Soft fade band between pool floor and white card body (title sits in this safe zone).
  const float title_top = stage_bottom + 2.0f;

  auto draw_home_icon_cluster = [&](float icon_size, float /*opacity_card*/) {
    // Stage 1 (home): rectangular 3-layer pool + full-color icon sitting in it.
    const float icon_cy = stage_top + (stage_bottom - stage_top) * 0.55f;
    auto paint_pool = [&]() {
      DrawStageWaveFill(app, rt, icon_stage, WaterLevel(app));
      DrawWaveIcon(app, rt, cx, icon_cy, icon_size, true);
    };
    // Clip pool to rounded card so L/R edges follow chrome (no rectangular red side seams).
    ID2D1RoundedRectangleGeometry *card_geo = nullptr;
    app->d2d->CreateRoundedRectangleGeometry(D2D1::RoundedRect(card, kCardRadius, kCardRadius),
                                             &card_geo);
    if (card_geo) {
      ID2D1Layer *layer = nullptr;
      if (SUCCEEDED(rt->CreateLayer(nullptr, &layer)) && layer) {
        rt->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), card_geo), layer);
        paint_pool();
        rt->PopLayer();
        layer->Release();
      } else {
        paint_pool();
      }
      card_geo->Release();
    } else {
      paint_pool();
    }
  };

  // Progress / transitional: stage-1 pool fades with the card; stage-2 is icon-only fill.
  if (progress_visual) {
    const float home_icon = 100.0f;
    const float progress_icon = 156.0f * app->icon_scale;
    const float icon_size = Lerp(home_icon, progress_icon, 1.0f - app->card_opacity);
    const float home_cy = stage_top + (stage_bottom - stage_top) * 0.55f;
    // Focus to true window center as card fades.
    const float icon_cy = Lerp(home_cy, height * 0.50f, 1.0f - app->card_opacity);

    if (app->card_opacity > 0.02f) {
      DrawCardChrome(rt, card, kCardRadius, app->card_opacity);
      // Stage-1 rectangular pool only while the home card is still dissolving.
      // During intro drain the tank empties with the same water level signal.
      ID2D1RoundedRectangleGeometry *card_geo = nullptr;
      app->d2d->CreateRoundedRectangleGeometry(D2D1::RoundedRect(card, kCardRadius, kCardRadius),
                                               &card_geo);
      if (card_geo) {
        ID2D1Layer *layer = nullptr;
        if (SUCCEEDED(rt->CreateLayer(nullptr, &layer)) && layer) {
          rt->PushLayer(D2D1::LayerParameters(D2D1::InfiniteRect(), card_geo), layer);
          // Fade tank with card so it vanishes as we enter install focus.
          const float tank_water = WaterLevel(app) * app->card_opacity;
          if (tank_water > 0.01f) {
            DrawStageWaveFill(app, rt, icon_stage, tank_water);
          }
          rt->PopLayer();
          layer->Release();
        }
        card_geo->Release();
      }
      DrawWindowCloseButton(app, rt, card, app->hover_window_close);
    } else {
      // Pure progress: no card / no rectangular tank.
      app->hit_window_close = {};
    }

    // Stage-2 object: water is constrained to the icon glyph only (same water-level logic).
    // After intro drain, level starts at 0 and rises with install progress.
    // When fill completes, keep drawing this final progress frame while finish options
    // fade in as a transparent overlay — avoid hard cut to a separate card layout.
    DrawWaveIcon(app, rt, cx, icon_cy, icon_size, false);

    if (!app->status.empty() && app->body_tf && muted && app->card_opacity < 0.55f) {
      // Centered under the icon (progress / finish transition).
      const float label_y = icon_cy + icon_size * 0.52f + 10.0f;
      DrawD2DText(rt, app->body_tf, muted, app->status,
                  D2D1::RectF(cx - 160, label_y, cx + 160, label_y + 26),
                  DWRITE_TEXT_ALIGNMENT_CENTER);
    }

    // During Finish transition: keep the progress icon in view while the home-style
    // wave pool + option card fade in (no hard cut). Full settled layout is below.
  } else if (app->page == Page::Home) {
    DrawCardChrome(rt, card, kCardRadius, 1.0f);
    // Stage-1: rectangular water pool + full-color icon. EXV stays on white below the pool.
    draw_home_icon_cluster(100.0f * app->icon_scale, 1.0f);
    DrawD2DText(rt, app->title_tf, brand, kAppTitle,
                D2D1::RectF(cx - 100, title_top, cx + 100, title_top + 38.0f));
    const float label_y = title_top + 40.0f;
    // Slightly roomier left/right insets for path field + browse (was 24).
    constexpr float kHomeSideInset = 32.0f;
    constexpr float kBrowseW = 52.0f;
    constexpr float kPathBrowseGap = 8.0f;
    DrawD2DText(rt, app->body_tf, muted, L"安装到",
                D2D1::RectF(card.left + kHomeSideInset, label_y, card.right - kHomeSideInset,
                            label_y + 18.0f));

    const float field_y = label_y + 18.0f;
    const auto path_rect =
        D2D1::RectF(card.left + kHomeSideInset, field_y,
                    card.right - (kHomeSideInset + kBrowseW + kPathBrowseGap), field_y + 34.0f);
    app->hit_path_field = path_rect;
    DrawPathField(rt, app->dwrite, app->body_tf, path_rect, app->install_dir, app->hover_path,
                  &app->path_truncated);

    app->hit_browse =
        D2D1::RectF(card.right - (kHomeSideInset + kBrowseW), field_y, card.right - kHomeSideInset,
                    field_y + 34.0f);
    DrawSecondaryButton(rt, app->button_tf, app->hit_browse, L"…", app->hover_browse, kBrandR,
                        kBrandG, kBrandB);

    // Keep comfortable gap between path field and install button (do not shrink this).
    // Bottom margin under the button is deliberately a little taller than before.
    constexpr float kPathToInstallGap = 16.0f;  // field height is 34 → top = field_y + 34 + gap
    app->hit_install = ButtonRect(cx, field_y + 34.0f + kPathToInstallGap, 180.0f, 40.0f);
    DrawPrimaryButton(rt, app->button_tf, app->hit_install, L"安装", app->hover_install, kBrandR,
                      kBrandG, kBrandB, app->install_dir_valid);

    // Inline validation message in the residual band under the install button.
    if (!app->install_dir_valid && !app->install_dir_error.empty() && app->body_tf) {
      ID2D1SolidColorBrush *warn = nullptr;
      rt->CreateSolidColorBrush(D2D1::ColorF(0.75f, 0.18f, 0.20f, 0.95f), &warn);
      if (warn) {
        DrawD2DText(rt, app->body_tf, warn, app->install_dir_error,
                    D2D1::RectF(card.left + kHomeSideInset, app->hit_install.bottom + 6.0f,
                                card.right - kHomeSideInset,
                                std::min(card.bottom - 10.0f, app->hit_install.bottom + 26.0f)));
        warn->Release();
      }
    }

    DrawWindowCloseButton(app, rt, card, app->hover_window_close);

    // Tooltips (500ms hold) — path full value / browse hint / close hint.
    if (app->path_truncated && app->path_tooltip_alpha > 0.05f) {
      DrawPathTooltip(rt, app->dwrite, app->body_tf, path_rect, app->install_dir,
                      app->path_tooltip_alpha);
    }
    if (app->browse_tooltip_alpha > 0.05f) {
      DrawTooltip(rt, app->dwrite, app->body_tf, app->hit_browse, L"选择安装位置",
                  app->browse_tooltip_alpha, 1);
    }
    if (app->close_tooltip_alpha > 0.05f) {
      DrawTooltip(rt, app->dwrite, app->body_tf, app->hit_window_close, L"退出安装",
                  app->close_tooltip_alpha, 2);
    }
  } else if (app->page == Page::Finish) {
    // Same composition as the home page: rounded card + rectangular wave pool in
    // the upper band (DrawStageWaveFill). Brand icon is a SOLID mark (not a
    // progress fill) so behind-pool wave motion does not clip the glyph.
    app->hit_window_close = {};
    app->target_visual_water = 0.82f;

    DrawCardChrome(rt, card, kCardRadius, 1.0f);
    draw_home_icon_cluster(100.0f * app->icon_scale, 1.0f);

    // Equal gaps: title→options == options→complete button. Window is taller only
    // on this page (kFinishWindowHeight); other stages keep compact height.
    const float title_h = 36.0f;
    const float opt_row_h = 22.0f;
    const float opt_row_gap = 12.0f;
    const float options_h = opt_row_h * 2.0f + opt_row_gap;
    const float btn_h = 40.0f;
    const float content_top = title_top + 6.0f;
    const float content_bottom = card.bottom - 18.0f;
    const float content_span = std::max(0.0f, content_bottom - content_top);
    // fixed = title + options + button; free space split into 3 equal gaps
    // (above title residual already in content_top, between title/options,
    // between options/button, and a bottom residual counted in content_bottom).
    const float fixed = title_h + options_h + btn_h;
    const float free = std::max(0.0f, content_span - fixed);
    // Two inter-section gaps must be equal (title→options and options→button).
    // Remaining free is split as small top residual under the pool.
    const float section_gap = free / 2.5f;  // equal primary gaps
    const float top_pad = free - section_gap * 2.0f;

    float y = content_top + std::max(4.0f, top_pad);
    DrawD2DText(rt, app->title_tf, brand, L"安装完成",
                D2D1::RectF(cx - 130, y, cx + 130, y + title_h));
    y += title_h + section_gap;

    const float col_gap = 18.0f;
    const float side_l = 34.0f;
    const float side_r = 22.0f;
    const float usable = card.right - card.left - side_l - side_r - col_gap;
    const float col_w = usable * 0.5f;
    const float left_x = card.left + side_l;
    const float right_x = left_x + col_w + col_gap;
    const float left_right = left_x + col_w;
    const float right_right = card.right - side_r;
    const float row0 = y;
    const float row1 = y + opt_row_h + opt_row_gap;
    DrawCheckbox(rt, app->dwrite, app->body_tf, brand, dark, left_x, row0, app->opt_desktop,
                 L"创建桌面快捷方式", left_right, &app->hit_check_desktop);
    DrawCheckbox(rt, app->dwrite, app->body_tf, brand, dark, right_x, row0, app->opt_start_menu,
                 L"开始菜单快捷方式", right_right, &app->hit_check_start);
    DrawCheckbox(rt, app->dwrite, app->body_tf, brand, dark, left_x, row1, app->opt_quick_launch,
                 L"快速启动栏", left_right, &app->hit_check_quick);
    DrawCheckbox(rt, app->dwrite, app->body_tf, brand, dark, right_x, row1, app->opt_launch,
                 L"立即打开 EXV", right_right, &app->hit_check_launch);

    const float btn_y = row1 + opt_row_h + section_gap;
    app->hit_finish = ButtonRect(cx, btn_y, 180.0f, btn_h);
    DrawPrimaryButton(rt, app->button_tf, app->hit_finish, L"完成", app->hover_finish, kBrandR,
                      kBrandG, kBrandB, true);
  } else if (app->page == Page::UninstallConfirm) {
    DrawCardChrome(rt, card, kCardRadius, 1.0f);
    // Compact vertical stack (icon / title / checkbox / button) so the primary
    // CTA stays inside the card instead of overflowing the bottom edge.
    const float icon_sz = 64.0f;
    const float title_h = 34.0f;
    const float opt_h = 24.0f;
    const float btn_h = 40.0f;
    const float fixed = icon_sz + title_h + opt_h + btn_h;
    const float free = std::max(0.0f, (card.bottom - card.top) - fixed);
    const float unit = free / 9.0f;
    const float m_top = unit * 2.0f;
    const float g_icon = unit * 2.0f;
    const float g_title = unit * 2.0f;
    const float g_opt = free - (m_top + g_icon + g_title + unit * 2.0f);
    const float m_bot = unit * 2.0f;
    (void)m_bot;
    float y = card.top + m_top;
    DrawWaveIcon(app, rt, cx, y + icon_sz * 0.5f, icon_sz, true);
    y += icon_sz + g_icon;
    DrawD2DText(rt, app->title_tf, brand, L"卸载 EXV",
                D2D1::RectF(cx - 120, y, cx + 120, y + title_h));
    y += title_h + g_title;
    // Center checkbox + label as one group under the title.
    const float box_w = 18.0f;
    const float box_gap = 10.0f;
    const float label_w = 6.0f * 14.5f;  // "清除用户数据"
    const float group_w = box_w + box_gap + label_w;
    const float check_x = cx - group_w * 0.5f;
    DrawCheckbox(rt, app->dwrite, app->body_tf, brand, dark, check_x, y,
                 app->opt_clear_user_data, L"清除用户数据", check_x + group_w + 8.0f,
                 &app->hit_check_clear);
    y += opt_h + std::max(10.0f, g_opt);
    app->hit_uninstall = ButtonRect(cx, y, 180.0f, btn_h);
    DrawPrimaryButton(rt, app->button_tf, app->hit_uninstall, L"卸载", app->hover_uninstall,
                      kBrandR, kBrandG, kBrandB);
    DrawWindowCloseButton(app, rt, card, app->hover_window_close);
    if (app->close_tooltip_alpha > 0.05f) {
      DrawTooltip(rt, app->dwrite, app->body_tf, app->hit_window_close, L"退出安装",
                  app->close_tooltip_alpha, 2);
    }
  } else if (app->page == Page::Done) {
    DrawCardChrome(rt, card, kCardRadius, 1.0f);
    // Primary close button only — no "退出安装" disc after work is finished.
    app->hit_window_close = {};
    // Match the install finish page rhythm: icon above title, button lower but
    // still inside the card.
    const float icon_sz = 64.0f;
    const float title_h = 36.0f;
    const float btn_h = 40.0f;
    const float fixed = icon_sz + title_h + btn_h;
    const float free = std::max(0.0f, (card.bottom - card.top) - fixed);
    const float unit = free / 7.0f;
    const float m_top = unit * 2.0f;
    const float g_icon = unit * 2.0f;
    const float g_title = unit * 2.0f;
    float y = card.top + m_top;
    DrawWaveIcon(app, rt, cx, y + icon_sz * 0.5f, icon_sz, true);
    y += icon_sz + g_icon;
    DrawD2DText(rt, app->title_tf, brand, L"已卸载",
                D2D1::RectF(cx - 100, y, cx + 100, y + title_h));
    y += title_h + g_title;
    app->hit_close = ButtonRect(cx, y, 180.0f, btn_h);
    DrawPrimaryButton(rt, app->button_tf, app->hit_close, L"有缘再会", app->hover_close, kBrandR,
                      kBrandG, kBrandB, true);
  } else if (app->page == Page::Error) {
    DrawCardChrome(rt, card, kCardRadius, 1.0f);
    // Keep the title high enough to read as the page heading and anchor the
    // primary action to the card bottom so it can never overflow the surface.
    const float title_h = 50.0f;
    const float body_h = 58.0f;
    const float btn_h = 40.0f;
    const float title_top = card.top + 76.0f;
    const float body_top = title_top + title_h + 14.0f;
    const float button_bottom = card.bottom - 28.0f;
    const float button_top = button_bottom - btn_h;
    DrawD2DText(rt, app->title_tf, brand, L"出错了",
                D2D1::RectF(cx - 100, title_top, cx + 100, title_top + title_h));
    DrawD2DText(rt, app->body_tf, dark, app->error.empty() ? L"未知错误" : app->error,
                D2D1::RectF(card.left + 24, body_top, card.right - 24, body_top + body_h));
    app->hit_close = ButtonRect(cx, button_top, 180.0f, btn_h);
    DrawPrimaryButton(rt, app->button_tf, app->hit_close, L"关闭", app->hover_close, kBrandR,
                      kBrandG, kBrandB);
    DrawWindowCloseButton(app, rt, card, app->hover_window_close);
    if (app->close_tooltip_alpha > 0.05f) {
      DrawTooltip(rt, app->dwrite, app->body_tf, app->hit_window_close, L"退出安装",
                  app->close_tooltip_alpha, 2);
    }
  }

  if (brand) {
    brand->Release();
  }
  if (dark) {
    dark->Release();
  }
  if (muted) {
    muted->Release();
  }
  if (white) {
    white->Release();
  }
}

D2D1_RENDER_TARGET_PROPERTIES DpiRtProps(UINT dpi, bool premultiplied) {
  const D2D1_PIXEL_FORMAT pf = D2D1::PixelFormat(
      DXGI_FORMAT_B8G8R8A8_UNORM,
      premultiplied ? D2D1_ALPHA_MODE_PREMULTIPLIED : D2D1_ALPHA_MODE_IGNORE);
  // Explicit dpiX/dpiY => DIPs: logical size = pixels * 96 / dpi (crisp on 125%/150%/200%).
  const float f = static_cast<float>(dpi);
  return D2D1::RenderTargetProperties(D2D1_RENDER_TARGET_TYPE_DEFAULT, pf, f, f,
                                      D2D1_RENDER_TARGET_USAGE_NONE, D2D1_FEATURE_LEVEL_DEFAULT);
}

bool EnsureHwndRt(AppState *app) {
  if (app->hwnd_rt) {
    return true;
  }
  RECT rc{};
  GetClientRect(app->hwnd, &rc);
  const D2D1_SIZE_U size = D2D1::SizeU(std::max(1L, rc.right - rc.left),
                                       std::max(1L, rc.bottom - rc.top));
  const auto props = DpiRtProps(app->dpi, false);
  return SUCCEEDED(app->d2d->CreateHwndRenderTarget(
      props, D2D1::HwndRenderTargetProperties(app->hwnd, size), &app->hwnd_rt));
}

bool EnsureDcRt(AppState *app) {
  if (app->dc_rt) {
    return true;
  }
  const auto props = DpiRtProps(app->dpi, true);
  return SUCCEEDED(app->d2d->CreateDCRenderTarget(&props, &app->dc_rt));
}

void DiscardDeviceTargets(AppState *app) {
  if (app->hwnd_rt) {
    app->hwnd_rt->Release();
    app->hwnd_rt = nullptr;
  }
  if (app->dc_rt) {
    app->dc_rt->Release();
    app->dc_rt = nullptr;
  }
  // Bitmaps are device-dependent on HWND/DC RT — drop and reload.
  ReleaseIconLayers(&app->icon_color, &app->icon_gray);
  app->icon_loaded = false;
}

bool PresentLayered(AppState *app) {
  RECT wr{};
  GetWindowRect(app->hwnd, &wr);
  const int width = std::max(1L, wr.right - wr.left);
  const int height = std::max(1L, wr.bottom - wr.top);

  HDC screen = GetDC(nullptr);
  HDC mem = CreateCompatibleDC(screen);
  BITMAPINFO bmi{};
  bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bmi.bmiHeader.biWidth = width;
  bmi.bmiHeader.biHeight = -height;  // top-down
  bmi.bmiHeader.biPlanes = 1;
  bmi.bmiHeader.biBitCount = 32;
  bmi.bmiHeader.biCompression = BI_RGB;
  void *bits = nullptr;
  HBITMAP dib = CreateDIBSection(mem, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
  if (dib == nullptr || bits == nullptr) {
    if (dib) {
      DeleteObject(dib);
    }
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return false;
  }
  HGDIOBJ old = SelectObject(mem, dib);
  // Clear premultiplied buffer.
  std::memset(bits, 0, static_cast<size_t>(width) * static_cast<size_t>(height) * 4);

  if (!EnsureDcRt(app)) {
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return false;
  }

  RECT bind{0, 0, width, height};
  if (FAILED(app->dc_rt->BindDC(mem, &bind))) {
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return false;
  }

  // Layout coordinates are DIPs; physical DIB is in device pixels.
  const float dip_w = PixelsToDips(static_cast<float>(width), app->dpi);
  const float dip_h = PixelsToDips(static_cast<float>(height), app->dpi);
  app->dc_rt->BeginDraw();
  PaintScene(app, app->dc_rt, dip_w, dip_h, true);
  const HRESULT hr = app->dc_rt->EndDraw();
  if (hr == D2DERR_RECREATE_TARGET) {
    DiscardDeviceTargets(app);
  }

  // D2D DC targets sometimes emit straight alpha; ULW requires premultiplied BGRA.
  // Premultiply in-place so the window is actually visible.
  if (bits != nullptr) {
    auto *px = static_cast<std::uint8_t *>(bits);
    const std::size_t count = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    for (std::size_t i = 0; i < count; ++i) {
      const std::uint8_t a = px[i * 4 + 3];
      if (a == 0) {
        px[i * 4 + 0] = 0;
        px[i * 4 + 1] = 0;
        px[i * 4 + 2] = 0;
      } else if (a < 255) {
        px[i * 4 + 0] = static_cast<std::uint8_t>((px[i * 4 + 0] * a) / 255);
        px[i * 4 + 1] = static_cast<std::uint8_t>((px[i * 4 + 1] * a) / 255);
        px[i * 4 + 2] = static_cast<std::uint8_t>((px[i * 4 + 2] * a) / 255);
      }
    }
  }

  // Never call SetLayeredWindowAttributes on this HWND — it fights per-pixel ULW and can make
  // the entire window invisible while the taskbar icon remains.
  POINT pt_src{0, 0};
  POINT pt_dst{wr.left, wr.top};
  SIZE size{width, height};
  BLENDFUNCTION blend{};
  blend.BlendOp = AC_SRC_OVER;
  blend.SourceConstantAlpha = 255;
  blend.AlphaFormat = AC_SRC_ALPHA;
  const BOOL ok = UpdateLayeredWindow(app->hwnd, screen, &pt_dst, &size, mem, &pt_src, 0, &blend,
                                      ULW_ALPHA);

  SelectObject(mem, old);
  DeleteObject(dib);
  DeleteDC(mem);
  ReleaseDC(nullptr, screen);
  return ok == TRUE;
}

void PresentHwnd(AppState *app) {
  if (!EnsureHwndRt(app) || app->hwnd_rt == nullptr) {
    return;
  }
  // GetSize() already returns DIPs when render target dpi is set correctly.
  app->hwnd_rt->BeginDraw();
  const auto size = app->hwnd_rt->GetSize();
  PaintScene(app, app->hwnd_rt, size.width, size.height, false);
  if (app->hwnd_rt->EndDraw() == D2DERR_RECREATE_TARGET) {
    DiscardDeviceTargets(app);
  }
}

int WindowHeightForPage(Page page) {
  // Only the install Finish page is taller so title→options can match
  // options→button spacing. Home / progress / uninstall keep the compact size.
  if (page == Page::Finish) {
    return kFinishWindowHeight;
  }
  return kWindowHeight;
}

void EnsureWindowSizeForPage(AppState *app) {
  if (app == nullptr || app->hwnd == nullptr) {
    return;
  }
  const int w = ScalePx(kWindowWidth, app->dpi);
  const int h = ScalePx(WindowHeightForPage(app->page), app->dpi);
  RECT wr{};
  GetWindowRect(app->hwnd, &wr);
  const int cur_w = wr.right - wr.left;
  const int cur_h = wr.bottom - wr.top;
  if (cur_w == w && cur_h == h) {
    return;
  }
  const int cx = (wr.left + wr.right) / 2;
  const int cy = (wr.top + wr.bottom) / 2;
  SetWindowPos(app->hwnd, nullptr, cx - w / 2, cy - h / 2, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
  DiscardDeviceTargets(app);
}

void ApplyDpi(AppState *app, UINT new_dpi, const RECT *suggested_bounds) {
  if (app == nullptr || new_dpi == 0) {
    return;
  }
  if (new_dpi == app->dpi && suggested_bounds == nullptr) {
    return;
  }
  app->dpi = new_dpi;
  // Device targets + bitmaps must be rebuilt for the new pixel density.
  DiscardDeviceTargets(app);

  if (suggested_bounds != nullptr) {
    SetWindowPos(app->hwnd, nullptr, suggested_bounds->left, suggested_bounds->top,
                 suggested_bounds->right - suggested_bounds->left,
                 suggested_bounds->bottom - suggested_bounds->top,
                 SWP_NOZORDER | SWP_NOACTIVATE);
  } else if (app->hwnd) {
    EnsureWindowSizeForPage(app);
  }
  InvalidateRect(app->hwnd, nullptr, FALSE);
}

void Present(AppState *app) {
  // Always use per-pixel alpha so the area outside the rounded card is truly transparent
  // and soft uniform shadows can blend against the desktop.
  // Do NOT mix SetLayeredWindowAttributes here — it breaks ULW visibility.
  if (!PresentLayered(app)) {
    // Last resort: opaque HWND RT (loses true transparency, but window stays usable).
    PresentHwnd(app);
  }
}

bool BrowseForFolder(HWND owner, std::wstring &path) {
  IFileDialog *dialog = nullptr;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&dialog)))) {
    return false;
  }
  DWORD opts = 0;
  dialog->GetOptions(&opts);
  dialog->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
  bool ok = false;
  if (SUCCEEDED(dialog->Show(owner))) {
    IShellItem *item = nullptr;
    if (SUCCEEDED(dialog->GetResult(&item)) && item) {
      PWSTR name = nullptr;
      if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &name)) && name) {
        path = name;
        CoTaskMemFree(name);
        ok = true;
      }
      item->Release();
    }
  }
  dialog->Release();
  return ok;
}

void ApplyFinishOptions(AppState *app) {
  // Start menu is already created during install (NSIS parity). Recreate if user re-checked.
  if (app->opt_start_menu) {
    CreateStartMenuShortcuts(app->install_dir);
  }
  if (app->opt_desktop) {
    if (!CreateDesktopShortcut(app->install_dir)) {
      MessageBoxW(app->hwnd, L"无法创建桌面快捷方式。请检查桌面路径权限。", L"EXV Setup",
                  MB_OK | MB_ICONWARNING);
    }
  }
  if (app->opt_quick_launch) {
    CreateQuickLaunchShortcut(app->install_dir);
  }
  if (app->opt_launch) {
    std::wstring err;
    if (!LaunchExvUi(app->install_dir, &err)) {
      const std::wstring msg =
          err.empty() ? std::wstring(L"无法启动 EXV。") : err;
      MessageBoxW(app->hwnd, msg.c_str(), L"EXV Setup", MB_OK | MB_ICONWARNING);
    }
  }
}

void KickInstallWorkerThread(AppState *app) {
  if (app->work_running || app->deferred_work_started) {
    return;
  }
  app->deferred_work_started = true;
  app->work_running = true;
  app->work_done = false;
  app->work_ok = false;
  // 停滞注入基准：从 worker 启动时刻算起，避免启动瞬间误判为停滞。
  app->last_engine_update_ms = static_cast<double>(GetTickCount64());
  app->stall_base = 0.0f;
  app->stall_water = 0.0f;

  app->progress_model.SetListener([app](double t, const std::wstring &status) {
    // Map engine progress 0→1 onto rising waterline (after intro drain).
    const float p = static_cast<float>(std::clamp(t, 0.0, 1.0));
    app->target_progress = p;
    // 引擎有真实推进 → 停滞注入基准更新，让真实进度接管。
    app->last_engine_update_ms = static_cast<double>(GetTickCount64());
    if (!app->intro_drain_active && !app->fill_water_before_finish) {
      // 全局单调：真实进度作为下限，绝不回退。
      app->target_visual_water = std::max(app->target_visual_water, p);
      app->stall_base = app->target_visual_water;
      app->stall_water = app->target_visual_water;
    }
    app->status = status;
  });

  app->worker = std::thread([app] {
    InstallRequest req;
    req.install_dir = app->install_dir;
    // Always create Start Menu during install (NSIS Section "Install").
    // Desktop / quick launch / launch stay finish-page / silent flags.
    req.create_start_menu = true;
    req.create_desktop_shortcut = false;
    req.create_quick_launch = false;
    req.launch_app = false;
    req.app_version = L"3.3.8";
    wchar_t env[4096] = {};
    if (GetEnvironmentVariableW(L"EXV_SETUP_PAYLOAD_DIR", env, 4096) > 0) {
      req.payload_path = env;
      req.payload_is_directory = true;
    }
    const auto result = RunInstall(req, &app->progress_model);
    app->work_ok = result.ok;
    app->error = result.error;
    if (result.ok && !result.install_dir.empty()) {
      app->install_dir = result.install_dir;
    }
    app->work_done = true;
    app->work_running = false;
    PostMessageW(app->hwnd, WM_APP + 1, 0, 0);
  });
}

void StartInstallWorker(AppState *app) {
  if (app->work_running || app->intro_drain_active || app->deferred_work_started) {
    return;
  }
  // Intro choreography: full-color icon grows, wave drains from top→bottom, colors desaturate.
  app->page = Page::Progress;
  app->intro_drain_active = true;
  app->deferred_work_started = false;
  app->target_progress = 0.0f;
  app->display_progress = 0.0f;
  app->visual_water = 1.0f;
  app->target_visual_water = 0.0f;
  app->icon_scale = 1.0f;
  app->status = L"";
  // Real install starts after drain finishes (see WM_TIMER).
}

void StartUninstallWorker(AppState *app) {
  if (app->work_running) {
    return;
  }
  app->work_running = true;
  app->work_done = false;
  app->work_ok = false;
  app->page = Page::UninstallProgress;
  app->target_progress = 0.0f;
  app->display_progress = 0.0f;
  // 停滞注入基准：从卸载 worker 启动时刻算起。
  app->last_engine_update_ms = static_cast<double>(GetTickCount64());
  app->stall_base = 1.0f;   // 卸载从满水开始，停滞注入向下蠕动
  app->stall_water = 1.0f;
  // Confirm/Done pages are dry (no wave). On progress only: start with a FULL
  // icon waterline and drain 1→0 with real milestones. Stay on pure progress
  // chrome (card_opacity=0) so we never paint the home rectangular tank, which
  // would look like a pool "popping in" from a dry confirm screen.
  app->visual_water = 1.0f;
  app->target_visual_water = 1.0f;
  app->icon_scale = 1.35f;
  app->card_opacity = 0.0f;
  app->intro_drain_active = false;
  app->fill_water_before_finish = false;
  app->status = L"正在开始卸载…";
  app->progress_model.SetListener([app](double t, const std::wstring &status) {
    const float p = static_cast<float>(std::clamp(t, 0.0, 1.0));
    app->target_progress = p;
    // 引擎有真实推进 → 停滞注入基准更新，让真实进度接管。
    app->last_engine_update_ms = static_cast<double>(GetTickCount64());
    // Uninstall: water falls with completed work (t=0 full, t=1 empty).
    // 全局单调：卸载水面只降不升（min 保护，停滞注入的下降在真实值之下）。
    app->target_visual_water = std::min(app->target_visual_water, 1.0f - p);
    app->stall_base = app->target_visual_water;
    app->stall_water = app->target_visual_water;
    app->status = status;
  });
  app->worker = std::thread([app] {
    UninstallRequest req;
    req.install_dir = app->install_dir;
    req.clear_user_data = app->opt_clear_user_data;
    const auto result = RunUninstall(req, &app->progress_model);
    app->work_ok = result.ok;
    app->error = result.error;
    app->work_done = true;
    app->work_running = false;
    PostMessageW(app->hwnd, WM_APP + 1, 0, 0);
  });
}

void EnterSuccessPage(AppState *app) {
  app->page = app->uninstall ? Page::Done : Page::Finish;
  // Install finish settles on the home-style wave-pool card. Icon is solid (no
  // progress clip). Grow the HWND only for Finish so other stages stay compact.
  app->card_opacity = app->uninstall ? 1.0f : 0.15f;
  app->visual_water = app->uninstall ? 0.0f : 0.82f;
  app->target_visual_water = app->visual_water;
  app->icon_scale = 1.0f;
  app->fill_water_before_finish = false;
  if (!app->uninstall) {
    app->status = L"安装完成";
    EnsureWindowSizeForPage(app);
  } else {
    app->status.clear();
    EnsureWindowSizeForPage(app);
  }
}

void OnWorkDone(AppState *app) {
  if (app->worker.joinable()) {
    app->worker.join();
  }
  app->intro_drain_active = false;
  app->deferred_work_started = false;
  if (!app->work_ok) {
    app->page = Page::Error;
    app->card_opacity = 1.0f;
    app->visual_water = 1.0f;
    app->target_visual_water = 1.0f;
    app->icon_scale = 1.0f;
    app->fill_water_before_finish = false;
    return;
  }
  if (app->uninstall) {
    // Uninstall already drives water 1→0 with progress; go straight to Done.
    EnterSuccessPage(app);
    return;
  }
  // Install: even if engine finished instantly, animate water to full before Finish.
  // Steps already drove the waterline; this is only the final top-up so finish =
  // last progress frame, not a hard cut to another layout.
  app->fill_water_before_finish = true;
  app->target_progress = 1.0f;
  app->target_visual_water = 1.0f;
  app->status = L"安装完成";
  // If already full enough, enter Finish immediately (same visual as progress end).
  if (app->visual_water >= 0.985f) {
    app->visual_water = 1.0f;
    EnterSuccessPage(app);
  }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
  AppState *app = g_app;
  switch (msg) {
    case WM_SIZE:
      DiscardDeviceTargets(app);
      InvalidateRect(hwnd, nullptr, FALSE);
      return 0;
    case WM_ERASEBKGND:
      return 1;
    case WM_PAINT: {
      PAINTSTRUCT ps;
      BeginPaint(hwnd, &ps);
      if (app) {
        Present(app);
      }
      EndPaint(hwnd, &ps);
      return 0;
    }
    case WM_TIMER:
      if (app) {
        app->wave_phase += 0.14f;
        app->display_progress = Lerp(app->display_progress, app->target_progress, 0.14f);

        // Intro drain: water drops quickly top→bottom; icon eases larger; card fades.
        if (app->intro_drain_active) {
          app->target_visual_water = 0.0f;
          app->visual_water = Lerp(app->visual_water, 0.0f, 0.18f);
          app->icon_scale = Lerp(app->icon_scale, 1.55f, 0.12f);
          if (app->visual_water < 0.03f) {
            app->visual_water = 0.0f;
            app->intro_drain_active = false;
            // Start real extract after the color-drain choreography.
            KickInstallWorkerThread(app);
          }
        } else if (app->fill_water_before_finish) {
          // Fast fill to full water after engine done, then enter Finish.
          // At full fill DrawWaveIcon switches to a solid brand mark (no wave clip).
          app->target_visual_water = 1.0f;
          app->visual_water = Lerp(app->visual_water, 1.0f, 0.28f);
          app->display_progress = Lerp(app->display_progress, 1.0f, 0.28f);
          app->icon_scale = Lerp(app->icon_scale, 1.35f, 0.12f);
          if (app->visual_water >= 0.995f) {
            app->visual_water = 1.0f;
            app->display_progress = 1.0f;
            EnterSuccessPage(app);
          }
        } else if (IsProgressPage(app->page)) {
          // Track engine progress with snappy but smooth water rise.
          // P2 停滞注入（阶段满值蠕动）：引擎某步阻塞 >1.2s 时，水面以 1%/s 朝当前阶段
          // 满值（引擎 SetStageSpan 声明的 end）蠕动，到达即停、绝不越过——卡住时依然
          // 有看得见的推进，又不会无界虚高到下一阶段（此前 4% 有界蠕动在「结束旧进程」
          // 这类阻塞阶段显得几乎不动）。引擎真实事件更新时 stall_base 随之推进，真实
          // 进度始终接管主导。
          const double now_ms = static_cast<double>(GetTickCount64());
          const double stall_ms = now_ms - app->last_engine_update_ms;
          constexpr double kStallThresholdMs = 1200.0;
          constexpr double kStallRatePerSec = 0.01;  // 卡住时水面 1%/s 蠕动
          if (app->work_running && stall_ms > kStallThresholdMs) {
            const bool water_falls = app->uninstall;
            // 当前阶段满值：安装 = 阶段 end；卸载 = 1 - 阶段 end（水面随完成度下降）。
            const double stage_end_t = app->progress_model.StageEnd();
            const float stage_end_water =
                water_falls ? static_cast<float>(1.0 - stage_end_t)
                            : static_cast<float>(stage_end_t);
            const double stalled_s = (stall_ms - kStallThresholdMs) / 1000.0;
            const float creep = static_cast<float>(kStallRatePerSec * stalled_s);
            const float stall_target =
                water_falls ? std::max(stage_end_water, app->stall_base - creep)
                            : std::min(stage_end_water, app->stall_base + creep);
            app->stall_water = stall_target;
            // 单调约束：安装只向上、卸载只向下；绝不越过阶段满值。
            if (water_falls) {
              app->target_visual_water = std::min(app->target_visual_water, app->stall_water);
            } else {
              app->target_visual_water = std::max(app->target_visual_water, app->stall_water);
            }
          }
          app->visual_water = Lerp(app->visual_water, app->target_visual_water, 0.18f);
          app->icon_scale = Lerp(app->icon_scale, 1.45f, 0.08f);
        } else if (app->page == Page::Home || app->page == Page::Finish) {
          // Idle home / finish card: same mostly-full rectangular pool.
          app->target_visual_water = 0.82f;
          app->visual_water = Lerp(app->visual_water, 0.82f, 0.2f);
          app->icon_scale = Lerp(app->icon_scale, 1.0f, 0.15f);
        } else {
          app->visual_water =
              Lerp(app->visual_water, app->target_visual_water, 0.15f);
          app->icon_scale = Lerp(app->icon_scale, 1.0f, 0.12f);
        }

        // Progress pages keep chrome fully transparent. Finish eases card_opacity
        // as an overlay alpha over the same progress scene (not a full card swap).
        const float target_card =
            (IsProgressPage(app->page) || app->fill_water_before_finish) ? 0.0f : 1.0f;
        app->card_opacity = Lerp(app->card_opacity, target_card,
                                 app->page == Page::Finish ? 0.12f : 0.16f);

        // Hover amounts ease toward pointer targets (no layout offset).
        auto ease_hover = [](float current, bool hot) {
          return Lerp(current, hot ? 1.0f : 0.0f, hot ? 0.28f : 0.18f);
        };
        if (app->pointer_inside) {
          app->hover_window_close =
              ease_hover(app->hover_window_close, Hit(app->pointer_x, app->pointer_y, app->hit_window_close));
        } else {
          app->hover_window_close = ease_hover(app->hover_window_close, false);
        }
        if (app->pointer_inside && !IsProgressPage(app->page)) {
          app->hover_install = ease_hover(app->hover_install, Hit(app->pointer_x, app->pointer_y, app->hit_install));
          app->hover_browse = ease_hover(app->hover_browse, Hit(app->pointer_x, app->pointer_y, app->hit_browse));
          app->hover_finish = ease_hover(app->hover_finish, Hit(app->pointer_x, app->pointer_y, app->hit_finish));
          app->hover_uninstall =
              ease_hover(app->hover_uninstall, Hit(app->pointer_x, app->pointer_y, app->hit_uninstall));
          app->hover_close = ease_hover(app->hover_close, Hit(app->pointer_x, app->pointer_y, app->hit_close));
          app->hover_path = ease_hover(app->hover_path, Hit(app->pointer_x, app->pointer_y, app->hit_path_field));
          app->hover_check_desktop =
              ease_hover(app->hover_check_desktop, Hit(app->pointer_x, app->pointer_y, app->hit_check_desktop));
          app->hover_check_start =
              ease_hover(app->hover_check_start, Hit(app->pointer_x, app->pointer_y, app->hit_check_start));
          app->hover_check_quick =
              ease_hover(app->hover_check_quick, Hit(app->pointer_x, app->pointer_y, app->hit_check_quick));
          app->hover_check_launch =
              ease_hover(app->hover_check_launch, Hit(app->pointer_x, app->pointer_y, app->hit_check_launch));
          app->hover_check_clear =
              ease_hover(app->hover_check_clear, Hit(app->pointer_x, app->pointer_y, app->hit_check_clear));
        } else {
          app->hover_install = ease_hover(app->hover_install, false);
          app->hover_browse = ease_hover(app->hover_browse, false);
          app->hover_finish = ease_hover(app->hover_finish, false);
          app->hover_uninstall = ease_hover(app->hover_uninstall, false);
          app->hover_close = ease_hover(app->hover_close, false);
          app->hover_path = ease_hover(app->hover_path, false);
          app->hover_check_desktop = ease_hover(app->hover_check_desktop, false);
          app->hover_check_start = ease_hover(app->hover_check_start, false);
          app->hover_check_quick = ease_hover(app->hover_check_quick, false);
          app->hover_check_launch = ease_hover(app->hover_check_launch, false);
          app->hover_check_clear = ease_hover(app->hover_check_clear, false);
        }

        // Tooltips: require ~500ms continuous hover, then fade in.
        auto hold = [](float &acc, bool hot) {
          if (hot) {
            acc = std::min(acc + (1.0f / 60.0f), 1.0f);
          } else {
            acc = 0.0f;
          }
          return hot && acc >= 0.50f;
        };
        const bool path_hot = app->pointer_inside && app->path_truncated &&
                              Hit(app->pointer_x, app->pointer_y, app->hit_path_field);
        const bool browse_hot =
            app->pointer_inside && Hit(app->pointer_x, app->pointer_y, app->hit_browse);
        // Exit-install disc only on pre-finish card pages (not Finish / Done).
        const bool close_disc_active =
            app->page == Page::Home || app->page == Page::UninstallConfirm ||
            app->page == Page::Error ||
            (IsProgressPage(app->page) && app->card_opacity > 0.02f);
        const bool close_hot = close_disc_active && app->pointer_inside &&
                               Hit(app->pointer_x, app->pointer_y, app->hit_window_close);
        const bool show_path = hold(app->path_hover_hold_s, path_hot);
        const bool show_browse = hold(app->browse_hover_hold_s, browse_hot);
        const bool show_close = hold(app->close_hover_hold_s, close_hot);
        app->path_tooltip_alpha =
            Lerp(app->path_tooltip_alpha, show_path ? 1.0f : 0.0f, show_path ? 0.22f : 0.28f);
        app->browse_tooltip_alpha = Lerp(app->browse_tooltip_alpha, show_browse ? 1.0f : 0.0f,
                                         show_browse ? 0.22f : 0.28f);
        app->close_tooltip_alpha =
            Lerp(app->close_tooltip_alpha, show_close ? 1.0f : 0.0f, show_close ? 0.22f : 0.28f);

        // Splash droplets live on stage-1 rectangular pool (home + brief card-fade).
        if (app->page == Page::Home ||
            (IsProgressPage(app->page) && app->card_opacity > 0.05f && app->intro_drain_active)) {
          const float pad = kShadowMarginDip;
          const float content_w = static_cast<float>(kContentWidth);
          const D2D1_RECT_F stage =
              D2D1::RectF(pad, pad + 28.0f, pad + content_w, pad + 150.0f);
          const float mean_y = stage.bottom - (stage.bottom - stage.top) * WaterLevel(app);
          UpdateDroplets(app, stage, mean_y, 1.0f / 60.0f);
        }

        // Layered window needs continuous Present (no automatic WM_PAINT for ULW).
        Present(app);
      }
      return 0;
    case WM_APP + 1:
      if (app) {
        OnWorkDone(app);
        InvalidateRect(hwnd, nullptr, FALSE);
      }
      return 0;
    case WM_DPICHANGED: {
      if (app) {
        const auto new_dpi = static_cast<UINT>(HIWORD(wparam));
        const RECT *suggested = reinterpret_cast<const RECT *>(lparam);
        ApplyDpi(app, new_dpi, suggested);
      }
      return 0;
    }
    case WM_MOUSEMOVE: {
      if (!app) {
        return 0;
      }
      // Track leave notifications.
      TRACKMOUSEEVENT tme{};
      tme.cbSize = sizeof(tme);
      tme.dwFlags = TME_LEAVE;
      tme.hwndTrack = hwnd;
      TrackMouseEvent(&tme);

      app->pointer_inside = true;
      app->pointer_x = PixelsToDips(static_cast<float>(GET_X_LPARAM(lparam)), app->dpi);
      app->pointer_y = PixelsToDips(static_cast<float>(GET_Y_LPARAM(lparam)), app->dpi);
      ApplyCursor(app);
      return 0;
    }
    case WM_MOUSELEAVE:
      if (app) {
        app->pointer_inside = false;
        app->hand_cursor = false;
        SetCursor(LoadCursor(nullptr, IDC_ARROW));
      }
      return 0;
    case WM_SETCURSOR: {
      if (app && LOWORD(lparam) == HTCLIENT) {
        ApplyCursor(app);
        return TRUE;
      }
      return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    case WM_LBUTTONDOWN: {
      if (!app) {
        return 0;
      }
      // Convert device pixels → DIPs so hit-tests match PaintScene layout units.
      const float x = PixelsToDips(static_cast<float>(GET_X_LPARAM(lparam)), app->dpi);
      const float y = PixelsToDips(static_cast<float>(GET_Y_LPARAM(lparam)), app->dpi);
      app->pointer_x = x;
      app->pointer_y = y;
      app->pointer_inside = true;
      ApplyCursor(app);

      // Top-right brand-red close disc — available on card pages (and transitional card).
      if (Hit(x, y, app->hit_window_close)) {
        if (app->work_running || IsProgressPage(app->page)) {
          const int ans = MessageBoxW(hwnd, L"安装正在进行，确定要退出吗？", L"EXV Setup",
                                      MB_YESNO | MB_ICONQUESTION);
          if (ans != IDYES) {
            return 0;
          }
        }
        DestroyWindow(hwnd);
        return 0;
      }

      if (app->page == Page::Home) {
        if (Hit(x, y, app->hit_browse)) {
          std::wstring dir = app->install_dir;
          if (BrowseForFolder(hwnd, dir)) {
            app->install_dir = dir;
            app->path_truncated = false;
            RefreshInstallDirValidity(app);
            InvalidateRect(hwnd, nullptr, FALSE);
          }
        } else if (Hit(x, y, app->hit_install)) {
          RefreshInstallDirValidity(app);
          if (!app->install_dir_valid) {
            // Disabled: ignore click. Message is already shown under the button.
            return 0;
          }
          StartInstallWorker(app);
          Present(app);
        }
      } else if (app->page == Page::Finish) {
        if (Hit(x, y, app->hit_check_desktop)) {
          app->opt_desktop = !app->opt_desktop;
        } else if (Hit(x, y, app->hit_check_start)) {
          app->opt_start_menu = !app->opt_start_menu;
        } else if (Hit(x, y, app->hit_check_quick)) {
          app->opt_quick_launch = !app->opt_quick_launch;
        } else if (Hit(x, y, app->hit_check_launch)) {
          app->opt_launch = !app->opt_launch;
        } else if (Hit(x, y, app->hit_finish)) {
          ApplyFinishOptions(app);
          DestroyWindow(hwnd);
          return 0;
        }
        InvalidateRect(hwnd, nullptr, FALSE);
      } else if (app->page == Page::UninstallConfirm) {
        if (Hit(x, y, app->hit_check_clear)) {
          app->opt_clear_user_data = !app->opt_clear_user_data;
          InvalidateRect(hwnd, nullptr, FALSE);
        } else if (Hit(x, y, app->hit_uninstall)) {
          StartUninstallWorker(app);
          Present(app);
        }
      } else if (app->page == Page::Done || app->page == Page::Error) {
        if (Hit(x, y, app->hit_close)) {
          DestroyWindow(hwnd);
        }
      }
      return 0;
    }
    case WM_NCHITTEST: {
      LRESULT hit = DefWindowProcW(hwnd, msg, wparam, lparam);
      if (hit == HTCLIENT && app) {
        POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
        ScreenToClient(hwnd, &pt);
        const float dip_x = PixelsToDips(static_cast<float>(pt.x), app->dpi);
        const float dip_y = PixelsToDips(static_cast<float>(pt.y), app->dpi);

        // Outside rounded content rect (shadow margin) is non-client nowhere.
        if (!Hit(dip_x, dip_y, app->content_rect) && app->content_rect.right > app->content_rect.left) {
          return HTNOWHERE;
        }

        // Progress surface is fully draggable (icon focus). Card pages: drag except controls.
        if (IsProgressPage(app->page)) {
          if (!Hit(dip_x, dip_y, app->hit_window_close)) {
            return HTCAPTION;
          }
        } else if (!IsInteractiveControl(app, dip_x, dip_y)) {
          return HTCAPTION;
        }
      }
      return hit;
    }
    case WM_KEYDOWN:
      if (wparam == VK_ESCAPE && app) {
        if (app->work_running || IsProgressPage(app->page)) {
          const int ans = MessageBoxW(hwnd, L"安装正在进行，确定要退出吗？", L"EXV Setup",
                                      MB_YESNO | MB_ICONQUESTION);
          if (ans != IDYES) {
            return 0;
          }
        }
        DestroyWindow(hwnd);
      }
      return 0;
    case WM_DESTROY:
      if (app && app->worker.joinable()) {
        app->worker.join();
      }
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(hwnd, msg, wparam, lparam);
  }
}

int RunGui(bool uninstall, const CliOptions &options) {
  EnableProcessDpiAwareness();

  AppState app;
  app.options = options;
  app.uninstall = uninstall;
  app.install_dir = ResolveGuiInstallDir(uninstall, options);
  app.opt_desktop = options.desktop_shortcut;
  app.opt_start_menu = options.start_menu;
  app.opt_quick_launch = options.quick_launch;
  app.opt_launch = options.launch_app;
  app.opt_clear_user_data = options.clear_user_data;
  app.page = uninstall ? Page::UninstallConfirm : Page::Home;
  app.card_opacity = 1.0f;
  // Home starts nearly full but not flood-filled (keeps organic wave silhouette).
  // Uninstall confirm/done have no rectangular wave — keep water dry so entering
  // uninstall progress cannot flash a full pool "from nowhere".
  app.visual_water = uninstall ? 0.0f : 0.82f;
  app.target_visual_water = app.visual_water;
  app.target_visual_water = app.visual_water;
  app.icon_scale = 1.0f;
  app.dpi = QuerySystemDpi();
  g_app = &app;
  RefreshInstallDirValidity(&app);

  if (FAILED(D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &app.d2d))) {
    MessageBoxW(nullptr, L"Direct2D unavailable", L"EXV Setup", MB_ICONERROR);
    return 1;
  }
  if (FAILED(DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory),
                                 reinterpret_cast<IUnknown **>(&app.dwrite)))) {
    return 1;
  }
  if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                              IID_PPV_ARGS(&app.wic)))) {
    return 1;
  }

  WNDCLASSW wc{};
  wc.lpfnWndProc = WndProc;
  wc.hInstance = GetModuleHandleW(nullptr);
  wc.lpszClassName = L"ExvSetupWindow";
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  // Load icon at system metrics size so the title/taskbar glyph is sharp under scaling.
  const int icon_cx = GetSystemMetrics(SM_CXICON);
  const int icon_cy = GetSystemMetrics(SM_CYICON);
  wc.hIcon = static_cast<HICON>(LoadImageW(wc.hInstance, MAKEINTRESOURCEW(IDI_EXV_SETUP), IMAGE_ICON,
                                           icon_cx, icon_cy, LR_DEFAULTCOLOR));
  if (wc.hIcon == nullptr) {
    wc.hIcon = LoadIconW(nullptr, reinterpret_cast<LPCWSTR>(IDI_APPLICATION));
  }
  wc.hbrBackground = nullptr;
  RegisterClassW(&wc);

  const DWORD style = WS_POPUP | WS_VISIBLE;
  const DWORD ex = WS_EX_APPWINDOW | WS_EX_LAYERED;
  const int w = ScalePx(kWindowWidth, app.dpi);
  const int h = ScalePx(kWindowHeight, app.dpi);
  const int screen_w = GetSystemMetrics(SM_CXSCREEN);
  const int screen_h = GetSystemMetrics(SM_CYSCREEN);
  const int x = (screen_w - w) / 2;
  const int y = (screen_h - h) / 2;

  app.hwnd = CreateWindowExW(ex, wc.lpszClassName, uninstall ? L"EXV 卸载" : L"EXV 安装", style, x,
                             y, w, h, nullptr, nullptr, wc.hInstance, nullptr);
  // After create, re-query window DPI (monitor of the window may differ from primary).
  app.dpi = QueryWindowDpi(app.hwnd);
  const int w2 = ScalePx(kWindowWidth, app.dpi);
  const int h2 = ScalePx(kWindowHeight, app.dpi);
  if (w2 != w || h2 != h) {
    SetWindowPos(app.hwnd, nullptr, (screen_w - w2) / 2, (screen_h - h2) / 2, w2, h2,
                 SWP_NOZORDER | SWP_NOACTIVATE);
  }

  // Important: do NOT call SetLayeredWindowAttributes — this window is per-pixel ULW only.
  SetTimer(app.hwnd, 1, 16, nullptr);
  ShowWindow(app.hwnd, SW_SHOW);
  // Immediate first frame so the user never sees a blank layered surface.
  Present(&app);
  UpdateWindow(app.hwnd);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }

  DiscardDeviceTargets(&app);
  ReleaseIconLayers(&app.icon_color, &app.icon_gray);
  ReleaseTextFormats(&app);
  if (app.wic) {
    app.wic->Release();
  }
  if (app.dwrite) {
    app.dwrite->Release();
  }
  if (app.d2d) {
    app.d2d->Release();
  }
  g_app = nullptr;
  return app.work_done && !app.work_ok ? 1 : 0;
}

}  // namespace

int RunInstallerGui(const CliOptions &options) {
  return RunGui(false, options);
}

int RunUninstallerGui(const CliOptions &options) {
  return RunGui(true, options);
}

}  // namespace exv::setup::ui
