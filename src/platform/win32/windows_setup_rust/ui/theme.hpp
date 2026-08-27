#pragma once

namespace exv::setup::ui {

// Brand red from assets/icons/icon.svg (#9A2034)
inline constexpr float kBrandR = 0x9A / 255.0f;
inline constexpr float kBrandG = 0x20 / 255.0f;
inline constexpr float kBrandB = 0x34 / 255.0f;

inline constexpr float kCardRadius = 22.0f;
// Soft uniform chrome shadow margin (DIPs), all four sides — similar feel to the main app frame.
inline constexpr float kShadowMarginDip = 16.0f;
// Card height: keep path↔install spacing; bottom pad under install stays modest but
// not flush (~20–24 after the small vertical grow).
// Install bottom ≈ card.top+300; content height ≈ 324.
inline constexpr int kContentWidth = 400;
inline constexpr int kContentHeight = 324;
inline constexpr int kWindowWidth = 432;   // content + shadow * 2
inline constexpr int kWindowHeight = 356;
// Finish page needs extra vertical room so title→options spacing can match
// options→complete-button spacing without crowding. Other stages keep kWindowHeight.
inline constexpr int kFinishContentHeight = 360;
inline constexpr int kFinishWindowHeight = 392;  // content + shadow * 2
inline constexpr int kProgressWindowSize = 280;

inline constexpr wchar_t kAppTitle[] = L"EXV";
inline constexpr wchar_t kFontFamily[] = L"Microsoft YaHei";
inline constexpr wchar_t kFontFamilyFallback[] = L"Segoe UI";

}  // namespace exv::setup::ui
