#include "ui/gfx.hpp"
#include <algorithm>
#include <cstdint>

namespace base {
bool TransparentBacking(HWND window, int w, int h, POINT origin) {
    if (w <= 0 || h <= 0 || std::uint64_t(w) * h > 64 * 1024 * 1024ull)
        return false;
    BITMAPINFO bitmap{};
    bitmap.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bitmap.bmiHeader.biWidth = w;
    bitmap.bmiHeader.biHeight = -h;
    bitmap.bmiHeader.biPlanes = 1;
    bitmap.bmiHeader.biBitCount = 32;
    bitmap.bmiHeader.biCompression = BI_RGB;
    const auto dc = CreateCompatibleDC(nullptr);
    if (!dc)
        return false;
    void* pixels{};
    const auto dib = CreateDIBSection(dc, &bitmap, DIB_RGB_COLORS, &pixels, nullptr, 0);
    if (!dib) {
        DeleteDC(dc);
        return false;
    }
    std::fill_n(static_cast<std::uint32_t*>(pixels), std::size_t(w) * h, 0x01000000u);
    const auto previous = SelectObject(dc, dib);
    SIZE size{w, h};
    POINT source{};
    BLENDFUNCTION blend{AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    const bool result =
        UpdateLayeredWindow(window, nullptr, &origin, &size, dc, &source, 0, &blend, ULW_ALPHA) != FALSE;
    SelectObject(dc, previous);
    DeleteObject(dib);
    DeleteDC(dc);
    return result;
}

}
