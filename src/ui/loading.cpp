#include "ui/loading.hpp"
#include "ui/draw.hpp"
#include <cstdio>

namespace base {
bool DrawLoading(float progress, ImVec2 viewport) {
    const LoadingLayout layout(viewport);
    const auto center = layout.center;
    auto* output = draw::List();
    const double time = ImGui::GetTime();
    constexpr ImU32 green_light = IM_COL32(130, 255, 155, 255);
    constexpr ImU32 green_dark = IM_COL32(25, 150, 65, 255);
    output->AddRectFilled(
        {center.x - 144, center.y - 64}, {center.x + 144, center.y + 82}, IM_COL32(0, 0, 0, 255), 8);
    constexpr const char* label = "loading...";
    const auto text_size = ImGui::CalcTextSize(label);
    draw::GradientText(output, {center.x - text_size.x * 0.5f, center.y - text_size.y * 0.5f}, label,
        green_light, green_dark, time, 1.2f);

    constexpr float tau = 6.28318530718f;
    const float rotation = static_cast<float>(std::fmod(time * 0.8, 1.0)) * tau;
    for (unsigned i = 0; i < 6; ++i) {
        const float angle = rotation + static_cast<float>(i) * tau / 6.0f;
        const float weight = static_cast<float>(i) / 5.0f;
        const auto color = IM_COL32(static_cast<int>(25 + 105 * weight),
            static_cast<int>(150 + 105 * weight), static_cast<int>(65 + 90 * weight), 255);
        output->AddCircleFilled(
            {center.x + std::cos(angle) * 11, center.y - 35 + std::sin(angle) * 11}, 2.3f, color, 16);
    }

    progress = std::isfinite(progress) ? std::clamp(progress, 0.0f, 1.0f) : 0.0f;
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

    ImGui::SetNextWindowPos(layout.cancel_min, ImGuiCond_Always);
    ImGui::SetNextWindowSize(layout.cancel_size, ImGuiCond_Always);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {0, 0});
    bool canceled{};
    if (ImGui::Begin("##loading_cancel", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBackground |
                ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoNav)) {
        ImGui::SetCursorPos({0, 0});
        canceled = ImGui::InvisibleButton("cancel", layout.cancel_size);
        auto* button = ImGui::GetWindowDrawList();
        const auto position = ImGui::GetItemRectMin();
        const ImVec2 end{position.x + layout.cancel_size.x, position.y + layout.cancel_size.y};
        const auto color = ImGui::IsItemActive() ? IM_COL32(130, 30, 40, 255)
            : ImGui::IsItemHovered() ? IM_COL32(205, 55, 67, 255) : IM_COL32(160, 42, 52, 255);
        button->AddRectFilled(position, end, color, 3);
        constexpr float font_size = 12.0f;
        const auto text = ImGui::GetFont()->CalcTextSizeA(font_size, 1000.0f, 0.0f, "cancel");
        button->AddText(ImGui::GetFont(), font_size,
            {position.x + (layout.cancel_size.x - text.x) * 0.5f,
                position.y + (layout.cancel_size.y - text.y) * 0.5f}, IM_COL32_WHITE, "cancel");
    }
    ImGui::End();
    ImGui::PopStyleVar();
    return canceled;
}
}
