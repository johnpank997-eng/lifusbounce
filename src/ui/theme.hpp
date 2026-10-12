#pragma once
#include <imgui.h>

namespace base::theme {
constexpr ImU32 background = IM_COL32(8, 11, 17, 255);
constexpr ImU32 content_bg = IM_COL32(12, 16, 24, 255);
constexpr ImU32 surface = IM_COL32(250, 252, 255, 255);
constexpr ImU32 surface_2 = IM_COL32(17, 23, 34, 255);
constexpr ImU32 surface_3 = IM_COL32(27, 36, 52, 255);
constexpr ImU32 surface_hover = IM_COL32(29, 43, 69, 255);
constexpr ImU32 surface_active = IM_COL32(37, 55, 88, 255);
constexpr ImU32 border = IM_COL32(42, 56, 80, 255);
constexpr ImU32 text_primary = IM_COL32(246, 249, 255, 255);
constexpr ImU32 text_secondary = IM_COL32(204, 215, 235, 255);
constexpr ImU32 text_muted = IM_COL32(136, 155, 187, 255);
constexpr ImU32 accent = IM_COL32(70, 110, 255, 255);
constexpr ImU32 accent_soft = IM_COL32(37, 57, 111, 255);
constexpr ImU32 accent_light = IM_COL32(232, 240, 255, 255);

constexpr float panel_width = 380.0f;
constexpr float panel_height = 470.0f;
constexpr float sidebar_width = 80.0f;
constexpr float header_height = 36.0f;
constexpr float content_top = 50.0f;
constexpr float pad = 14.0f;
constexpr float rounding = 5.0f;
constexpr float rounding_box = 3.0f;
constexpr float rounding_small = 2.0f;
constexpr float row_height = 28.0f;
constexpr float row_gap = 2.0f;
constexpr float toggle_width = 32.0f;
constexpr float toggle_height = 16.0f;
constexpr float swatch_size = 16.0f;
constexpr float swatch_gap = 8.0f;
constexpr float value_width = 168.0f;
constexpr float content_width = panel_width - sidebar_width - pad * 2.0f;
constexpr float content_height = panel_height - content_top - pad - 4.0f;

inline void Apply() {
    ImGui::StyleColorsDark();
    auto& ui = ImGui::GetStyle();
    ui.WindowRounding = rounding;
    ui.ChildRounding = ui.PopupRounding = ui.FrameRounding = rounding_box;
    ui.GrabRounding = ui.ScrollbarRounding = ui.TabRounding = rounding_box;
    ui.WindowBorderSize = 0.0f;
    ui.PopupBorderSize = 1.0f;
    ui.FrameBorderSize = 0.0f;
    ui.WindowPadding = {0.0f, 0.0f};
    ui.ItemSpacing = {8.0f, row_gap};
    const auto set = [&](ImGuiCol slot, ImU32 color) {
        ui.Colors[slot] = ImGui::ColorConvertU32ToFloat4(color);
    };
    set(ImGuiCol_WindowBg, background);
    ui.Colors[ImGuiCol_ChildBg] = {0, 0, 0, 0};
    set(ImGuiCol_PopupBg, surface_2);
    set(ImGuiCol_Text, text_primary);
    set(ImGuiCol_TextDisabled, text_muted);
    set(ImGuiCol_FrameBg, surface_2);
    set(ImGuiCol_FrameBgHovered, surface_hover);
    set(ImGuiCol_FrameBgActive, surface_active);
    set(ImGuiCol_Border, border);
    set(ImGuiCol_Button, surface_3);
    set(ImGuiCol_ButtonHovered, surface_hover);
    set(ImGuiCol_ButtonActive, accent);
    set(ImGuiCol_CheckMark, accent);
    set(ImGuiCol_SliderGrab, accent);
    set(ImGuiCol_SliderGrabActive, accent_light);
    set(ImGuiCol_Header, accent_soft);
    set(ImGuiCol_HeaderHovered, surface_hover);
    set(ImGuiCol_HeaderActive, accent);
    set(ImGuiCol_Separator, border);
    set(ImGuiCol_TextSelectedBg, accent_soft);
}
}
