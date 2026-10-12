#include "ui/overlay_internal.hpp"
#include "ui/overlay.hpp"
#include "sdk/session.hpp"
#include "sdk/aim.hpp"
#include "ui/gfx.hpp"
#include "ui/operator_badges.hpp"
#include "ui/theme.hpp"
#include "ui/keybind.hpp"
#include "ui/draw.hpp"
#include "ui/frame_pacing.hpp"
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <chrono>
#include <array>
#include <string>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include <windowsx.h>
#include "resource.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace base {
float ui_alpha = 1.0f;
ImVec2 panel_min{}, panel_max{};
constexpr ImU32 green_light = IM_COL32(130, 255, 155, 255);
constexpr ImU32 green_dark = IM_COL32(25, 150, 65, 255);

ImU32 Fade(ImU32 c) {
    const unsigned a = static_cast<unsigned>(((c >> IM_COL32_A_SHIFT) & 0xFF) * ui_alpha);
    return (c & ~IM_COL32_A_MASK) | (a << IM_COL32_A_SHIFT);
}

float RowTextY(float top) {
    return top + (theme::row_height - ImGui::GetTextLineHeight()) * 0.5f;
}

float Animate(const char* name, float target, float speed) {
    auto* state = ImGui::GetStateStorage();
    const auto id = ImGui::GetID(name);
    const float previous = state->GetFloat(id, target);
    const float t = 1.0f - std::exp(-speed * std::min(ImGui::GetIO().DeltaTime, 0.05f));
    const float value = previous + (target - previous) * t;
    const float result = std::abs(value - target) < 0.001f ? target : value;
    state->SetFloat(id, result);
    return result;
}

ImU32 LerpColor(ImU32 a, ImU32 b, float t) {
    t = std::clamp(t, 0.0f, 1.0f);
    const float r = ((a >> 0) & 0xFF) * (1 - t) + ((b >> 0) & 0xFF) * t;
    const float g = ((a >> 8) & 0xFF) * (1 - t) + ((b >> 8) & 0xFF) * t;
    const float bl = ((a >> 16) & 0xFF) * (1 - t) + ((b >> 16) & 0xFF) * t;
    const float al = ((a >> 24) & 0xFF) * (1 - t) + ((b >> 24) & 0xFF) * t;
    return IM_COL32((int)r, (int)g, (int)bl, (int)al);
}

void RowHighlight(ImDrawList* draw, ImVec2 cursor, float width, float height, float t) {
    if (t <= 0.004f)
        return;
    draw->AddRectFilled(cursor, {cursor.x + width, cursor.y + height},
        Fade((theme::accent & ~IM_COL32_A_MASK) | (static_cast<ImU32>(32.0f * t) << IM_COL32_A_SHIFT)),
        theme::rounding_box);
}

void DrawBrand(ImDrawList* draw, ImVec2 position) {
    const double time = ImGui::GetTime();
    draw::GradientRect(draw, position, {position.x + theme::panel_width, position.y + theme::header_height},
        Fade(IM_COL32(70, 110, 255, 22)), Fade(IM_COL32(255, 255, 255, 12)), time, 0.2f, theme::rounding);
    const ImVec2 center{position.x + 21, position.y + theme::header_height * 0.5f};
    const int logo = draw->VtxBuffer.Size;
    draw->AddCircleFilled(center, 9, IM_COL32_WHITE, 48);
    draw->AddRectFilled({center.x - 9, center.y - 9}, center, IM_COL32_WHITE);
    draw::ShadeGradient(
        draw, logo, position.x, theme::panel_width, Fade(theme::text_primary), Fade(theme::accent), time);
    draw::GradientRect(draw, {position.x + 1, position.y + theme::header_height},
        {position.x + theme::panel_width - 1, position.y + theme::header_height + 1},
        Fade(theme::text_primary), Fade(theme::accent), time);
    draw::GradientText(draw,
        {position.x + 38, position.y + (theme::header_height - ImGui::GetTextLineHeight()) * 0.5f},
        "lifusbounce", Fade(theme::text_primary), Fade(theme::accent), time);
}

void DrawSwitch(ImDrawList* draw, ImVec2 pos, float on) {
    constexpr float radius = 5.5f;
    draw->AddRectFilled(pos, {pos.x + theme::toggle_width, pos.y + theme::toggle_height},
        Fade(LerpColor(theme::surface_3, theme::accent, on)), theme::toggle_height * 0.5f);
    draw->AddRect(pos, {pos.x + theme::toggle_width, pos.y + theme::toggle_height}, Fade(theme::border),
        theme::toggle_height * 0.5f);
    draw->AddCircleFilled({pos.x + radius + 2 + on * (theme::toggle_width - 2 * radius - 4),
                              pos.y + theme::toggle_height * 0.5f},
        radius, Fade(theme::surface), 24);
}

bool ToggleRow(const char* label, bool* value, float* color) {
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const float width = ImGui::GetContentRegionAvail().x;
    const ImVec2 cursor = ImGui::GetCursorScreenPos();

    ImGui::PushID(label);
    const bool pressed = ImGui::InvisibleButton("##row", {width, theme::row_height});
    const bool hovered = ImGui::IsItemHovered();
    const ImVec2 mouse = ImGui::GetIO().MousePos;

    const ImVec2 tpos{
        cursor.x + width - theme::toggle_width, cursor.y + (theme::row_height - theme::toggle_height) * 0.5f};

    ImVec2 sw_min{}, sw_max{};
    bool on_swatch = false;
    if (color) {
        const float s = theme::swatch_size;
        sw_min = {tpos.x - theme::swatch_gap - s, cursor.y + (theme::row_height - s) * 0.5f};
        sw_max = {sw_min.x + s, sw_min.y + s};
        on_swatch = hovered && mouse.x >= sw_min.x && mouse.x <= sw_max.x && mouse.y >= sw_min.y &&
            mouse.y <= sw_max.y;
    }

    if (pressed && on_swatch)
        ImGui::OpenPopup("##cpick");
    else if (pressed)
        *value = !*value;

    const float hover = Animate("hover", hovered ? 1.0f : 0.0f);
    RowHighlight(draw, cursor, width, theme::row_height, hover);
    draw->AddText({cursor.x, RowTextY(cursor.y)},
        Fade(LerpColor(theme::text_secondary, theme::text_primary, hover)), label);

    if (color) {
        draw->AddRectFilled(sw_min, sw_max,
            Fade(IM_COL32((int)(color[0] * 255), (int)(color[1] * 255), (int)(color[2] * 255), 255)),
            theme::rounding_small);
    }
    DrawSwitch(draw, tpos, Animate("switch", *value ? 1.0f : 0.0f, 12.0f));

    if (color) {
        constexpr ImVec2 size{156.0f, 136.0f};
        const float popup_alpha = Animate("popup", ImGui::IsPopupOpen("##cpick") ? 1.0f : 0.0f, 22.0f);
        ImVec2 at{sw_max.x - size.x, sw_max.y + 4.0f};
        if (at.y + size.y > panel_max.y - 8.0f)
            at.y = sw_min.y - 4.0f - size.y;
        at.x = std::clamp(at.x, panel_min.x + 8.0f, panel_max.x - size.x - 8.0f);
        at.y = std::clamp(at.y, panel_min.y + 8.0f, panel_max.y - size.y - 8.0f);
        ImGui::SetNextWindowPos(at);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {8, 8});
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ui_alpha * popup_alpha);
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImGui::ColorConvertU32ToFloat4(theme::surface_2));
        ImGui::PushStyleColor(ImGuiCol_Border, {0, 0, 0, 0});
        if (ImGui::BeginPopup("##cpick")) {
            ImGui::SetNextItemWidth(140.0f);
            ImGui::ColorPicker3("##p", color,
                ImGuiColorEditFlags_NoSidePreview | ImGuiColorEditFlags_NoSmallPreview |
                    ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoAlpha |
                    ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_PickerHueBar);
            ImGui::EndPopup();
        }
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);
    }

    ImGui::PopID();
    return pressed && !on_swatch;
}

void CustomSlider(const char* label, float* value, float v_min, float v_max, float step) {
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const float width = ImGui::GetContentRegionAvail().x;
    const ImVec2 cursor = ImGui::GetCursorScreenPos();
    const float label_h = ImGui::GetTextLineHeight();
    const float track_h = 4.0f, base_r = 7.0f;
    const float track_y = cursor.y + label_h + 10.0f;
    const bool coarse = v_max - v_min > 50.0f;

    ImGui::PushID(label);
    const float height = label_h + 23.0f;
    ImGui::InvisibleButton("##slider", {width, height});
    const bool hovered = ImGui::IsItemHovered();
    const bool active = ImGui::IsItemActive();
    if (active) {
        const float t =
            std::clamp((ImGui::GetIO().MousePos.x - cursor.x - base_r) / (width - 2.0f * base_r), 0.0f, 1.0f);
        const float raw = v_min + t * (v_max - v_min);
        *value = coarse ? std::round(raw) : std::round(raw / step) * step;
    }

    const float hover = Animate("hover", hovered || active ? 1.0f : 0.0f);
    const float shown = Animate("value", std::clamp((*value - v_min) / (v_max - v_min), 0.0f, 1.0f), 22.0f);
    ImGui::PopID();

    RowHighlight(draw, cursor, width, height, hover);
    draw->AddText(
        {cursor.x, cursor.y}, Fade(LerpColor(theme::text_secondary, theme::text_primary, hover)), label);
    char buf[16];
    snprintf(buf, sizeof(buf), coarse ? "%.0f" : step < 0.1f ? "%.2f" : "%.1f", *value);
    draw->AddText({cursor.x + width - ImGui::CalcTextSize(buf).x, cursor.y},
        Fade(LerpColor(theme::text_muted, theme::accent, hover)), buf);

    const float kx = cursor.x + base_r + shown * (width - 2.0f * base_r);
    const ImVec2 track_min{cursor.x, track_y}, track_max{cursor.x + width, track_y + track_h};
    draw->AddRectFilled(track_min, track_max, Fade(theme::surface_3), 2);
    draw->AddRectFilled(track_min, {kx, track_max.y}, Fade(theme::accent), 2);
    draw->AddCircleFilled({kx, track_y + track_h * 0.5f}, 5.0f + hover, Fade(theme::surface), 28);
}

bool ChoiceRow(const char* label, const char* selected, bool dropdown) {
    const auto cursor = ImGui::GetCursorScreenPos();
    const auto width = ImGui::GetContentRegionAvail().x;
    ImGui::PushID(label);
    const bool pressed = ImGui::InvisibleButton("##choice", {width, theme::row_height});
    auto* draw = ImGui::GetWindowDrawList();
    const float hover = Animate("hover", ImGui::IsItemHovered() ? 1.0f : 0.0f);
    RowHighlight(draw, cursor, width, theme::row_height, hover);
    draw->AddText({cursor.x, RowTextY(cursor.y)},
        Fade(LerpColor(theme::text_secondary, theme::text_primary, hover)), label);
    const ImVec2 min{cursor.x + width - theme::value_width, cursor.y + 3};
    const ImVec2 max{cursor.x + width, cursor.y + theme::row_height - 3};
    draw->AddRectFilled(
        min, max, Fade(LerpColor(theme::surface_3, theme::surface_hover, hover)), theme::rounding_box);
    draw->AddRect(min, max, Fade(LerpColor(theme::border, theme::accent, hover * 0.5f)), theme::rounding_box);
    const float available = theme::value_width - (dropdown ? 26.0f : 12.0f);
    const float text_width = ImGui::CalcTextSize(selected).x;
    const float font_size = ImGui::GetFontSize() * std::min(1.0f, available / std::max(text_width, 1.0f));
    draw->AddText(ImGui::GetFont(), font_size, {min.x + 6, cursor.y + (theme::row_height - font_size) * 0.5f},
        Fade(theme::text_primary), selected);
    if (dropdown) {
        const float x = max.x - 11, y = cursor.y + theme::row_height * 0.5f;
        draw->AddLine({max.x - 21, min.y + 1}, {max.x - 21, max.y - 1}, Fade(theme::border));
        draw->AddTriangleFilled({x - 4, y - 2}, {x + 4, y - 2}, {x, y + 2}, Fade(theme::text_primary));
    }
    ImGui::PopID();
    return pressed;
}

bool ActionButton(const char* label) {
    const auto cursor = ImGui::GetCursorScreenPos();
    const float width = ImGui::GetContentRegionAvail().x;
    ImGui::PushID(label);
    const bool pressed = ImGui::InvisibleButton("##action", {width, theme::row_height});
    const float hover = Animate("hover", ImGui::IsItemHovered() ? 1.0f : 0.0f);
    const float active = Animate("press", ImGui::IsItemActive() ? 1.0f : 0.0f, 24.0f);
    auto* draw = ImGui::GetWindowDrawList();
    const ImVec2 min{cursor.x, cursor.y + active};
    const ImVec2 max{cursor.x + width, cursor.y + theme::row_height};
    draw->AddRectFilled(min, max,
        Fade(LerpColor(IM_COL32(160, 42, 52, 255), IM_COL32(205, 55, 67, 255), hover)), theme::rounding_box);
    draw->AddRect(min, max, Fade(IM_COL32(230, 75, 85, 255)), theme::rounding_box);
    draw->AddText({cursor.x + (width - ImGui::CalcTextSize(label).x) * 0.5f, RowTextY(cursor.y) + active},
        Fade(theme::text_primary), label);
    ImGui::PopID();
    return pressed;
}

bool DebugControls() {
    return ActionButton("reload software");
}

bool MenuFrame(ImVec2 position, int& selected) {
    auto* draw = ImGui::GetWindowDrawList();
    panel_min = position;
    panel_max = {position.x + theme::panel_width, position.y + theme::panel_height};
    draw->AddRectFilled(position, panel_max, Fade(theme::background), theme::rounding);
    draw->AddRectFilled({position.x + theme::sidebar_width, position.y + theme::header_height}, panel_max,
        Fade(theme::content_bg), theme::rounding, ImDrawFlags_RoundCornersBottomRight);
    draw->AddRect(position, panel_max, Fade(theme::border), theme::rounding);
    DrawBrand(draw, position);
    constexpr const char* names[]{"esp", "aim", "debug"};
    for (int tab = 0; tab < static_cast<int>(std::size(names)); ++tab) {
        const float top = theme::content_top + tab * (theme::row_height + 6);
        ImGui::SetCursorPos({6, top});
        ImGui::PushID(tab);
        if (ImGui::InvisibleButton("##tab", {theme::sidebar_width - 12, theme::row_height}))
            selected = tab;
        const float hover = Animate("hover", ImGui::IsItemHovered() ? 1.0f : 0.0f);
        const float selection = Animate("selection", selected == tab ? 1.0f : 0.0f, 10.0f);
        draw->AddRectFilled({position.x + 6, position.y + top},
            {position.x + theme::sidebar_width - 6, position.y + top + theme::row_height},
            Fade(LerpColor(theme::background, theme::surface_hover, hover)), theme::rounding_box);
        draw->AddRectFilled({position.x + 6, position.y + top},
            {position.x + theme::sidebar_width - 6, position.y + top + theme::row_height},
            Fade((theme::accent & ~IM_COL32_A_MASK) |
                (static_cast<ImU32>(255 * selection) << IM_COL32_A_SHIFT)),
            theme::rounding_box);
        draw->AddText({position.x + 18, position.y + RowTextY(top)},
            Fade(LerpColor(theme::text_secondary, theme::text_primary, std::max(selection, hover))),
            names[tab]);
        ImGui::PopID();
    }
    ImGui::SetCursorPos({theme::panel_width - 24, 10});
    const bool close = ImGui::InvisibleButton("##close", {16, 14});
    const ImVec2 min{panel_max.x - 24, position.y + 10};
    const auto color = Fade(LerpColor(theme::text_muted, theme::text_primary,
        Animate("close_hover", ImGui::IsItemHovered() ? 1.0f : 0.0f)));
    draw->AddLine({min.x + 4, min.y + 3}, {min.x + 12, min.y + 11}, color);
    draw->AddLine({min.x + 12, min.y + 3}, {min.x + 4, min.y + 11}, color);
    return close;
}

void DrawLoading(float progress, ImVec2 viewport) {
    auto* output = draw::List();
    const double time = ImGui::GetTime();
    const ImVec2 center{viewport.x * 0.5f, std::max(64.0f, viewport.y - 96.0f)};
    output->AddRectFilled(
        {center.x - 144, center.y - 64}, {center.x + 144, center.y + 72}, IM_COL32(0, 0, 0, 255), 8);
    constexpr const char* label = "loading...";
    const auto text_size = ImGui::CalcTextSize(label);
    draw::GradientText(output, {center.x - text_size.x * 0.5f, center.y - text_size.y * 0.5f}, label,
        green_light, green_dark, time, 1.2f);

    constexpr float tau = 6.28318530718f;
    const float rotation = static_cast<float>(std::fmod(time * 0.8, 1.0)) * tau;
    for (unsigned i = 0; i < 6; ++i) {
        const float angle = rotation + static_cast<float>(i) * tau / 6.0f;
        const auto color = LerpColor(green_dark, green_light, static_cast<float>(i) / 5.0f);
        output->AddCircleFilled(
            {center.x + std::cos(angle) * 11, center.y - 35 + std::sin(angle) * 11}, 2.3f, color, 16);
    }

    progress = std::clamp(progress, 0.0f, 1.0f);
    constexpr float width = 240.0f;
    const ImVec2 min{center.x - width * 0.5f, center.y + 22};
    const ImVec2 max{min.x + width, min.y + 6};
    output->AddRectFilled(min, max, IM_COL32(20, 65, 35, 170), 3);
    if (progress > 0)
        draw::GradientRect(
            output, min, {min.x + width * progress, max.y}, green_dark, green_light, time, 1.2f, 3);
    char percentage[8]{};
    snprintf(percentage, sizeof(percentage), "%.1f%%", static_cast<double>(progress) * 100.0);
    draw::GradientText(output, {center.x - ImGui::CalcTextSize(percentage).x * 0.5f, max.y + 8}, percentage,
        green_light, green_dark, time, 1.2f);
}

void DrawPlayerStatus(const char* text) {
    auto* output = draw::List();
    const auto size = ImGui::CalcTextSize(text);
    output->AddRectFilled({18, 18}, {38 + size.x, 34 + size.y}, IM_COL32(0, 0, 0, 160), 6);
    draw::GradientText(output, {28, 26}, text, green_light, green_dark, ImGui::GetTime(), 1.2f);
}

}
