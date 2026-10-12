#pragma once
#include <imgui.h>
#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>
#include <string_view>
#include "sdk/skeleton.hpp"

namespace base::draw {
inline ImDrawList* List() {
    return ImGui::GetBackgroundDrawList();
}

inline void Line(ImVec2 from, ImVec2 to, ImU32 color, float width = 1.0f) {
    List()->AddLine(from, to, color, width);
}

inline void Rect(ImVec2 min, ImVec2 max, ImU32 color, float width = 1.0f) {
    List()->AddRect(min, max, color, 0.0f, 0, width);
}

inline void Circle(ImVec2 center, float radius, ImU32 color, float width = 1.0f) {
    List()->AddCircle(center, radius, color, 0, width);
}

inline void Text(ImVec2 position, ImU32 color, const char* value) {
    List()->AddText(position, color, value);
}

inline void ShadeGradient(ImDrawList* output, int first_vertex, float left, float span, ImU32 a, ImU32 b,
    double time, float cycles = 0.2f) {
    const auto from = ImGui::ColorConvertU32ToFloat4(a);
    const auto to = ImGui::ColorConvertU32ToFloat4(b);
    constexpr float tau = 6.28318530718f;
    const float phase = static_cast<float>(std::fmod(time * cycles, 1.0)) * tau;
    for (int i = first_vertex; i < output->VtxBuffer.Size; ++i) {
        auto& vertex = output->VtxBuffer[i];
        const float blend = 0.5f + 0.5f * std::sin((vertex.pos.x - left) / span * 3.14159265359f - phase);
        const float coverage = static_cast<float>((vertex.col >> IM_COL32_A_SHIFT) & 0xff) / 255.0f;
        vertex.col = ImGui::ColorConvertFloat4ToU32(
            {from.x + (to.x - from.x) * blend, from.y + (to.y - from.y) * blend,
                from.z + (to.z - from.z) * blend, (from.w + (to.w - from.w) * blend) * coverage});
    }
}

inline void GradientText(ImDrawList* output, ImVec2 position, const char* value, ImU32 a, ImU32 b,
    double time, float cycles = 0.2f) {
    const int first = output->VtxBuffer.Size;
    output->AddText(position, IM_COL32_WHITE, value);
    ShadeGradient(
        output, first, position.x, std::max(ImGui::CalcTextSize(value).x, 1.0f), a, b, time, cycles);
}

inline void GradientRect(ImDrawList* output, ImVec2 min, ImVec2 max, ImU32 a, ImU32 b, double time,
    float cycles = 0.2f, float rounding = 0.0f) {
    const int first = output->VtxBuffer.Size;
    output->AddRectFilled(min, max, IM_COL32_WHITE, rounding);
    ShadeGradient(output, first, min.x, std::max(max.x - min.x, 1.0f), a, b, time, cycles);
}

class ScreenPose {
    const base::sdk::skeleton::Nodes& nodes_;
    const base::sdk::skeleton::Projection& projection_;
    std::array<std::optional<base::sdk::skeleton::Pixel>,
        static_cast<unsigned>(base::sdk::skeleton::Bone::count)>
        points_{};
    std::array<bool, static_cast<unsigned>(base::sdk::skeleton::Bone::count)> computed_{};

  public:
    ScreenPose(const base::sdk::skeleton::Nodes& nodes, const base::sdk::skeleton::Projection& camera)
        : nodes_(nodes), projection_(camera) {}

    [[nodiscard]] bool Has(base::sdk::skeleton::Bone bone) const {
        const auto index = static_cast<unsigned>(bone);
        return index < nodes_.size() && nodes_[index].has_value();
    }

    [[nodiscard]] std::optional<base::sdk::skeleton::Pixel> Get(base::sdk::skeleton::Bone bone) {
        const auto index = static_cast<unsigned>(bone);
        if (index >= nodes_.size())
            return std::nullopt;
        if (!computed_[index]) {
            if (nodes_[index])
                points_[index] = projection_.Project(*nodes_[index]);
            computed_[index] = true;
        }
        return points_[index];
    }
};

inline bool LineVisible(ImVec2 a, ImVec2 b, ImVec2 min, ImVec2 max, float width) {

    const float margin = width + 2.0f;
    return std::max(a.x, b.x) >= min.x - margin && std::min(a.x, b.x) <= max.x + margin &&
        std::max(a.y, b.y) >= min.y - margin && std::min(a.y, b.y) <= max.y + margin;
}

inline void Skeleton(ScreenPose& points, ImVec2 viewport_origin, ImVec2 viewport_size, ImU32 color,
    float width = 1.0f, bool feet = false, bool fingers = false,
    const base::sdk::skeleton::CircleGeometry* head = nullptr) {
    auto* output = List();
    output->PushClipRect(
        viewport_origin, {viewport_origin.x + viewport_size.x, viewport_origin.y + viewport_size.y}, true);
    const auto draw_edge = [&](const auto& edge, bool trim_head = false) {
        if (!points.Has(edge[0]) || !points.Has(edge[1]))
            return;
        const auto a = points.Get(edge[0]), b = points.Get(edge[1]);
        if (a && b) {
            ImVec2 start{viewport_origin.x + a->x, viewport_origin.y + a->y};
            const ImVec2 end{viewport_origin.x + b->x, viewport_origin.y + b->y};
            if (trim_head && head) {
                const ImVec2 center{viewport_origin.x + head->center.x, viewport_origin.y + head->center.y};
                const float dx = end.x - center.x, dy = end.y - center.y;
                const float length = std::hypot(dx, dy);
                if (length <= head->radius)
                    return;
                start = {center.x + dx * head->radius / length, center.y + dy * head->radius / length};
            }
            if (LineVisible(start, end, viewport_origin,
                    {viewport_origin.x + viewport_size.x, viewport_origin.y + viewport_size.y}, width))
                output->AddLine(start, end, color, width);
        }
    };
    for (const auto& edge : base::sdk::skeleton::edges)
        draw_edge(edge,
            edge[0] == base::sdk::skeleton::Bone::head_joint &&
                edge[1] == base::sdk::skeleton::Bone::neck_joint);
    if (feet)
        for (const auto& edge : base::sdk::skeleton::foot_edges)
            draw_edge(edge);
    if (fingers)
        for (const auto& edge : base::sdk::skeleton::finger_edges)
            draw_edge(edge);
    output->PopClipRect();
}

inline void Skeleton(const base::sdk::skeleton::Nodes& nodes, const base::sdk::skeleton::Matrix& matrix,
    ImVec2 viewport_origin, ImVec2 viewport_size, ImU32 color, float width = 1.0f, bool feet = false,
    bool fingers = false, const base::sdk::skeleton::CircleGeometry* head = nullptr) {
    const base::sdk::skeleton::Projection camera(matrix, viewport_size.x, viewport_size.y);
    ScreenPose points(nodes, camera);
    Skeleton(points, viewport_origin, viewport_size, color, width, feet, fingers, head);
}

inline void HeadCircle(const base::sdk::skeleton::CircleGeometry& geometry, ImVec2 viewport_origin,
    ImVec2 viewport_size, ImU32 color, float width = 1.0f) {
    const ImVec2 center{viewport_origin.x + geometry.center.x, viewport_origin.y + geometry.center.y};
    if (!LineVisible({center.x - geometry.radius, center.y - geometry.radius},
            {center.x + geometry.radius, center.y + geometry.radius}, viewport_origin,
            {viewport_origin.x + viewport_size.x, viewport_origin.y + viewport_size.y}, width))
        return;
    auto* output = List();
    output->PushClipRect(
        viewport_origin, {viewport_origin.x + viewport_size.x, viewport_origin.y + viewport_size.y}, true);
    output->AddCircle(center, geometry.radius, color, 0, width);
    output->PopClipRect();
}

struct ScreenBounds {
    ImVec2 min, max;
};

inline std::optional<ScreenBounds> SkeletonBounds(ScreenPose& points, float line_width, bool feet,
    bool fingers, const base::sdk::skeleton::CircleGeometry* head) {
    const float limit = std::numeric_limits<float>::max();
    ScreenBounds result{{limit, limit}, {-limit, -limit}};
    unsigned count{};
    const auto include = [&](float x, float y) {
        result.min.x = std::min(result.min.x, x);
        result.min.y = std::min(result.min.y, y);
        result.max.x = std::max(result.max.x, x);
        result.max.y = std::max(result.max.y, y);
        ++count;
    };
    const auto edges = [&](const auto& connections) {
        for (const auto& edge : connections) {
            if (!points.Has(edge[0]) || !points.Has(edge[1]))
                continue;
            const auto from = points.Get(edge[0]), to = points.Get(edge[1]);
            if (!from || !to)
                return false;
            include(from->x, from->y);
            include(to->x, to->y);
        }
        return true;
    };

    if (!edges(base::sdk::skeleton::edges) || (feet && !edges(base::sdk::skeleton::foot_edges)) ||
        (fingers && !edges(base::sdk::skeleton::finger_edges)))
        return std::nullopt;
    if (head) {
        if (!std::isfinite(head->center.x) || !std::isfinite(head->center.y) ||
            !std::isfinite(head->radius) || head->radius <= 0.0f)
            return std::nullopt;
        include(head->center.x - head->radius, head->center.y - head->radius);
        include(head->center.x + head->radius, head->center.y + head->radius);
    }
    if (!count || !std::isfinite(line_width) || line_width <= 0.0f)
        return std::nullopt;
    const float padding = 2.0f + line_width * 0.5f;
    result.min = {result.min.x - padding, result.min.y - padding};
    result.max = {result.max.x + padding, result.max.y + padding};
    const float width = result.max.x - result.min.x, height = result.max.y - result.min.y;
    if (!std::isfinite(width) || !std::isfinite(height) || width <= 0.0f || height <= 0.0f)
        return std::nullopt;
    return result;
}

inline std::optional<ScreenBounds> SkeletonBounds(const base::sdk::skeleton::Nodes& nodes,
    const base::sdk::skeleton::Matrix& matrix, ImVec2 viewport_size, float line_width, bool feet,
    bool fingers, const base::sdk::skeleton::CircleGeometry* head) {
    const base::sdk::skeleton::Projection camera(matrix, viewport_size.x, viewport_size.y);
    ScreenPose points(nodes, camera);
    return SkeletonBounds(points, line_width, feet, fingers, head);
}

inline void Box(const ScreenBounds& bounds, ImVec2 viewport_size, ImU32 color, float width) {
    if (!LineVisible(bounds.min, bounds.max, {0, 0}, viewport_size, width))
        return;
    auto* output = List();
    output->PushClipRect({0, 0}, viewport_size, true);
    output->AddRect(bounds.min, bounds.max, color, 0.0f, 0, width);
    output->PopClipRect();
}

inline ImU32 HealthColor(int current) {
    const float ratio = static_cast<float>(std::clamp(current, 0, 100)) * 0.01f;
    const int red = ratio <= 0.66f ? 255 : static_cast<int>(255.0f * (1.0f - (ratio - 0.66f) / 0.34f));
    const int green = ratio <= 0.33f ? static_cast<int>(128.0f * ratio / 0.33f)
        : ratio <= 0.66f             ? static_cast<int>(128.0f + 127.0f * (ratio - 0.33f) / 0.33f)
                                     : 255;
    return IM_COL32(red, green, 0, 255);
}

inline float HealthFillTop(float displayed, const ScreenBounds& bounds) {
    return bounds.max.y - 1.0f -
        std::max(0.0f, bounds.max.y - bounds.min.y - 2.0f) * std::clamp(displayed, 0.0f, 100.0f) * 0.01f;
}

inline void Health(
    int current, float& displayed, const ScreenBounds& bounds, ImVec2 viewport_size, bool show_bar = true) {
    const float left = bounds.min.x, top = bounds.min.y, bottom = bounds.max.y;
    const float target = static_cast<float>(std::clamp(current, 0, 100));
    if (!std::isfinite(displayed))
        displayed = target;
    displayed = std::clamp(displayed, 0.0f, 100.0f);
    const auto delta = ImGui::GetIO().DeltaTime;
    if (displayed <= target)
        displayed = target;
    else if (std::isfinite(delta) && delta > 0.0f)
        displayed = std::max(target, displayed - 255.0f * delta);
    if (!show_bar)
        return;

    auto* output = List();
    output->PushClipRect({0, 0}, viewport_size, true);
    const auto rectangle = [&](ImVec2 min, ImVec2 max, ImU32 color) {
        min = {std::clamp(min.x, 0.0f, viewport_size.x), std::clamp(min.y, 0.0f, viewport_size.y)};
        max = {std::clamp(max.x, 0.0f, viewport_size.x), std::clamp(max.y, 0.0f, viewport_size.y)};
        if (max.x > min.x && max.y > min.y)
            output->AddRectFilled(min, max, color);
    };
    rectangle({left - 7.0f, top}, {left - 3.0f, bottom}, IM_COL32_BLACK);
    if (displayed > 0.0f)
        rectangle({left - 6.0f, HealthFillTop(displayed, bounds)}, {left - 4.0f, bottom - 1.0f},
            HealthColor(current));
    output->PopClipRect();
}

inline void ShadowText(
    ImDrawList* output, ImFont* font, float font_size, ImVec2 position, ImU32 color, std::string_view value) {
    constexpr float offset = 0.75f;
    output->AddText(font, font_size, {position.x + offset, position.y + offset}, color & IM_COL32_A_MASK,
        value.data(), value.data() + value.size());
    output->AddText(font, font_size, position, color, value.data(), value.data() + value.size());
}

inline constexpr float label_base_font_size = 13.0f;

inline float LabelScale(float distance) {
    return std::isfinite(distance) && distance >= 0.0f
        ? std::clamp(1.0f / std::sqrt(1.0f + distance / 40.0f), 2.0f / 3.0f, 1.0f)
        : 1.0f;
}

inline void HealthNumber(
    int current, float displayed, const ScreenBounds& bounds, ImVec2 viewport_size, float distance) {
    char buffer[4];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), std::clamp(current, 0, 100));
    const std::string_view value(buffer, static_cast<std::size_t>(result.ptr - buffer));
    auto* font = ImGui::GetFont();
    const float scale = LabelScale(distance);
    const float font_size = 12.0f * scale;
    const auto size = font->CalcTextSizeA(
        font_size, std::numeric_limits<float>::max(), 0.0f, value.data(), value.data() + value.size());

    const ImVec2 position{bounds.min.x - 7.0f - 3.0f * scale - size.x,
        std::clamp(HealthFillTop(displayed, bounds) - size.y * 0.5f, bounds.min.y,
            std::max(bounds.min.y, bounds.max.y - size.y))};
    auto* output = List();
    output->PushClipRect({0, 0}, viewport_size, true);
    ShadowText(output, font, font_size, position, HealthColor(current), value);
    output->PopClipRect();
}

inline void EquipmentLabel(std::string_view value, const ScreenBounds& bounds, ImVec2 viewport_size,
    ImU32 color, float distance, unsigned row = 0) {
    if (value.empty())
        return;
    auto* font = ImGui::GetFont();
    const float scale = LabelScale(distance);
    const float font_size = label_base_font_size * scale;
    const auto size = font->CalcTextSizeA(
        font_size, std::numeric_limits<float>::max(), 0.0f, value.data(), value.data() + value.size());
    const ImVec2 position{(bounds.min.x + bounds.max.x - size.x) * 0.5f,
        bounds.max.y + 4.0f * scale + (font_size + 6.0f * scale) * row};
    auto* output = List();
    output->PushClipRect({0, 0}, viewport_size, true);
    ShadowText(output, font, font_size, position, color, value);
    output->PopClipRect();
}

inline void NameTag(std::string_view value, bool show_name, bool show_icon, bool show_defuser,
    ImTextureID texture, const ScreenBounds& bounds, ImVec2 viewport_size, ImU32 color, float distance,
    ImTextureID defuser_texture = ImTextureID{}) {
    show_icon = show_icon && texture != ImTextureID{};
    show_defuser = show_defuser && defuser_texture != ImTextureID{};
    if (!show_name && !show_icon && !show_defuser)
        return;
    if (show_name && value.empty())
        value = "unknown";
    auto* font = ImGui::GetFont();

    const float scale = LabelScale(distance);
    const float font_size = label_base_font_size * scale;
    const auto size = show_name ? font->CalcTextSizeA(font_size, std::numeric_limits<float>::max(), 0.0f,
                                      value.data(), value.data() + value.size())
                                : ImVec2{};
    const float height = 24.0f * scale;
    const float icon_size = 24.0f * scale;
    const float defuser_size = 16.0f * scale;
    const float gap = 3.0f * scale;
    const float name_gap = 5.0f * scale;
    float width = show_icon ? icon_size : 0.0f;
    if (show_defuser && show_icon)
        width += gap;
    const float defuser_left = width;
    if (show_defuser)
        width += defuser_size;
    if (show_name && (show_icon || show_defuser))
        width += show_defuser ? name_gap : gap;
    const float name_left = width;
    width += size.x;
    const ImVec2 position{(bounds.min.x + bounds.max.x - width) * 0.5f, bounds.min.y - height - 4.0f * scale};
    auto* output = List();
    output->PushClipRect({0, 0}, viewport_size, true);
    if (show_icon) {
        const ImVec2 icon{position.x, position.y + (height - icon_size) * 0.5f};
        output->AddImage(texture, icon, {icon.x + icon_size, icon.y + icon_size});
    }
    if (show_defuser) {
        const ImVec2 icon{position.x + defuser_left, position.y + (height - defuser_size) * 0.5f};
        output->AddImage(defuser_texture, icon, {icon.x + defuser_size, icon.y + defuser_size});
    }
    if (show_name)
        ShadowText(output, font, font_size, {position.x + name_left, position.y + (height - size.y) * 0.5f},
            color, value);
    output->PopClipRect();
}
}
