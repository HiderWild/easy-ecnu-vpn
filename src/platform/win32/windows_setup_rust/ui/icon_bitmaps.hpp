#pragma once

#include <d2d1.h>
#include <wincodec.h>

namespace exv::setup::ui {

// Loads the branded icon into two D2D bitmaps: full color and grayscale.
// Prefers embedded PNG resource, then file path fallbacks.
bool LoadIconLayers(ID2D1RenderTarget *rt,
                    IWICImagingFactory *wic,
                    ID2D1Bitmap **out_color,
                    ID2D1Bitmap **out_gray);

void ReleaseIconLayers(ID2D1Bitmap **color, ID2D1Bitmap **gray);

}  // namespace exv::setup::ui
