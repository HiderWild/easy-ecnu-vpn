#pragma once

namespace exv::ui_shell {

struct WindowBounds {
  int width = 0;
  int height = 0;
};

inline constexpr int kWindowShadowMarginPx = 0;
inline constexpr WindowBounds kAppSurfaceAdvancedWindowBounds{879, 563};
inline constexpr WindowBounds kAppSurfaceMinimalWindowBounds{328, 136};
inline constexpr WindowBounds kElectronAdvancedWindowBounds{
    kAppSurfaceAdvancedWindowBounds.width + kWindowShadowMarginPx * 2,
    kAppSurfaceAdvancedWindowBounds.height + kWindowShadowMarginPx * 2};
inline constexpr WindowBounds kElectronMinimalWindowBounds{
    kAppSurfaceMinimalWindowBounds.width + kWindowShadowMarginPx * 2,
    kAppSurfaceMinimalWindowBounds.height + kWindowShadowMarginPx * 2};

[[nodiscard]] constexpr WindowBounds advanced_window_bounds() noexcept {
  return kElectronAdvancedWindowBounds;
}

[[nodiscard]] constexpr WindowBounds minimal_window_bounds() noexcept {
  return kElectronMinimalWindowBounds;
}

} // namespace exv::ui_shell
