#pragma once
#include <imgui.h>
#include <algorithm>
#include <cmath>

namespace base {
struct LoadingLayout {
    ImVec2 center;
    ImVec2 cancel_min;
    ImVec2 cancel_size;

    explicit LoadingLayout(ImVec2 viewport)
        : center{viewport.x * 0.5f, std::max(64.0f, viewport.y - 96.0f)},
          cancel_min{std::floor(std::clamp(center.x - 32.0f, 0.0f, std::max(0.0f, viewport.x - 64.0f))),
              std::floor(std::clamp(center.y + 52.0f, 0.0f, std::max(0.0f, viewport.y - 20.0f)))},
          cancel_size{std::min(64.0f, std::max(1.0f, viewport.x)),
              std::min(20.0f, std::max(1.0f, viewport.y))} {}
};

bool DrawLoading(float progress, ImVec2 viewport);
}
