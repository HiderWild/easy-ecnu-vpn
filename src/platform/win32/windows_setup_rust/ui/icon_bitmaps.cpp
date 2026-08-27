#include "windows_setup_rust/ui/icon_bitmaps.hpp"

#include "windows_setup_rust/resource.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>
#include <vector>

namespace exv::setup::ui {
namespace {

bool DecodeFrameToBitmaps(ID2D1RenderTarget *rt,
                          IWICImagingFactory *wic,
                          IWICBitmapFrameDecode *frame,
                          ID2D1Bitmap **out_color,
                          ID2D1Bitmap **out_gray) {
  if (rt == nullptr || wic == nullptr || frame == nullptr || out_color == nullptr ||
      out_gray == nullptr) {
    return false;
  }

  IWICFormatConverter *converter = nullptr;
  if (FAILED(wic->CreateFormatConverter(&converter))) {
    return false;
  }
  const HRESULT hr = converter->Initialize(frame, GUID_WICPixelFormat32bppPBGRA,
                                           WICBitmapDitherTypeNone, nullptr, 0.0,
                                           WICBitmapPaletteTypeMedianCut);
  if (FAILED(hr)) {
    converter->Release();
    return false;
  }

  UINT width = 0;
  UINT height = 0;
  converter->GetSize(&width, &height);
  if (width == 0 || height == 0) {
    converter->Release();
    return false;
  }

  const UINT stride = width * 4;
  const UINT size = stride * height;
  std::vector<BYTE> color_pixels(size);
  if (FAILED(converter->CopyPixels(nullptr, stride, size, color_pixels.data()))) {
    converter->Release();
    return false;
  }
  converter->Release();

  std::vector<BYTE> gray_pixels = color_pixels;
  for (UINT i = 0; i + 3 < size; i += 4) {
    // Premultiplied BGRA.
    const BYTE b = color_pixels[i + 0];
    const BYTE g = color_pixels[i + 1];
    const BYTE r = color_pixels[i + 2];
    const BYTE a = color_pixels[i + 3];
    // Luma (same premultiplied alpha channel).
    const unsigned luma =
        (static_cast<unsigned>(r) * 54 + static_cast<unsigned>(g) * 183 +
         static_cast<unsigned>(b) * 19) /
        256;
    // Soft gray with a hint of brand desaturation.
    const BYTE y = static_cast<BYTE>(luma);
    gray_pixels[i + 0] = y;
    gray_pixels[i + 1] = y;
    gray_pixels[i + 2] = y;
    gray_pixels[i + 3] = a;
  }

  const D2D1_BITMAP_PROPERTIES props = D2D1::BitmapProperties(
      D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED));

  ID2D1Bitmap *color = nullptr;
  ID2D1Bitmap *gray = nullptr;
  if (FAILED(rt->CreateBitmap(D2D1::SizeU(width, height), color_pixels.data(), stride, props,
                              &color))) {
    return false;
  }
  if (FAILED(rt->CreateBitmap(D2D1::SizeU(width, height), gray_pixels.data(), stride, props,
                              &gray))) {
    color->Release();
    return false;
  }
  *out_color = color;
  *out_gray = gray;
  return true;
}

bool LoadFromFile(ID2D1RenderTarget *rt,
                  IWICImagingFactory *wic,
                  const wchar_t *path,
                  ID2D1Bitmap **out_color,
                  ID2D1Bitmap **out_gray) {
  IWICBitmapDecoder *decoder = nullptr;
  if (FAILED(wic->CreateDecoderFromFilename(path, nullptr, GENERIC_READ,
                                            WICDecodeMetadataCacheOnLoad, &decoder))) {
    return false;
  }
  IWICBitmapFrameDecode *frame = nullptr;
  const bool ok =
      SUCCEEDED(decoder->GetFrame(0, &frame)) &&
      DecodeFrameToBitmaps(rt, wic, frame, out_color, out_gray);
  if (frame) {
    frame->Release();
  }
  decoder->Release();
  return ok;
}

bool LoadFromResourcePng(ID2D1RenderTarget *rt,
                         IWICImagingFactory *wic,
                         ID2D1Bitmap **out_color,
                         ID2D1Bitmap **out_gray) {
  HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_EXV_ICON_PNG), (LPCWSTR)RT_RCDATA);
  if (res == nullptr) {
    return false;
  }
  HGLOBAL loaded = LoadResource(nullptr, res);
  if (loaded == nullptr) {
    return false;
  }
  const DWORD size = SizeofResource(nullptr, res);
  void *data = LockResource(loaded);
  if (data == nullptr || size == 0) {
    return false;
  }

  IWICStream *stream = nullptr;
  if (FAILED(wic->CreateStream(&stream))) {
    return false;
  }
  if (FAILED(stream->InitializeFromMemory(static_cast<BYTE *>(data), size))) {
    stream->Release();
    return false;
  }
  IWICBitmapDecoder *decoder = nullptr;
  if (FAILED(wic->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnLoad,
                                          &decoder))) {
    stream->Release();
    return false;
  }
  IWICBitmapFrameDecode *frame = nullptr;
  const bool ok =
      SUCCEEDED(decoder->GetFrame(0, &frame)) &&
      DecodeFrameToBitmaps(rt, wic, frame, out_color, out_gray);
  if (frame) {
    frame->Release();
  }
  decoder->Release();
  stream->Release();
  return ok;
}

std::wstring ModuleDir() {
  wchar_t path[MAX_PATH] = {};
  GetModuleFileNameW(nullptr, path, MAX_PATH);
  std::wstring p(path);
  const auto slash = p.find_last_of(L"\\/");
  if (slash != std::wstring::npos) {
    p.resize(slash);
  }
  return p;
}

}  // namespace

bool LoadIconLayers(ID2D1RenderTarget *rt,
                    IWICImagingFactory *wic,
                    ID2D1Bitmap **out_color,
                    ID2D1Bitmap **out_gray) {
  if (LoadFromResourcePng(rt, wic, out_color, out_gray)) {
    return true;
  }

  const auto dir = ModuleDir();
  const wchar_t *candidates[] = {
      L"\\..\\..\\assets\\icons\\icons\\256x256.png",
      L"\\..\\..\\assets\\icons\\icon.png",
      L"\\assets\\icons\\icons\\256x256.png",
      L"\\assets\\icons\\icon.png",
  };
  for (const auto *rel : candidates) {
    const auto full = dir + rel;
    if (LoadFromFile(rt, wic, full.c_str(), out_color, out_gray)) {
      return true;
    }
  }

  // Absolute repo-relative attempt via current directory variants is already covered.
  // Last resort: load ICO if present next to assets.
  if (LoadFromFile(rt, wic, (dir + L"\\..\\..\\assets\\icons\\icon.ico").c_str(), out_color,
                   out_gray)) {
    return true;
  }
  return false;
}

void ReleaseIconLayers(ID2D1Bitmap **color, ID2D1Bitmap **gray) {
  if (color && *color) {
    (*color)->Release();
    *color = nullptr;
  }
  if (gray && *gray) {
    (*gray)->Release();
    *gray = nullptr;
  }
}

}  // namespace exv::setup::ui
