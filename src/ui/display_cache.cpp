#include "ui/overlay_internal.hpp"
#include <imgui_impl_win32.h>
#include <windowsx.h>
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace base {
auto DisplayCache::Clear() -> void {
    frame.reset();
    poses.clear();
}

auto DisplayCache::Update(std::shared_ptr<const sdk::Snapshot> next) -> bool {
    if (next == frame)
        return false;
    const bool changed = !frame || frame->epoch != next->epoch || frame->camera != next->camera ||
        frame->local_player != next->local_player;
    if (changed)
        poses.clear();
    std::erase_if(poses, [&](const auto& item) {
        return item.first == next->local_player ||
            !std::binary_search(next->present.begin(), next->present.end(), item.first);
    });
    for (const auto& entity : next->GetPlayers()) {
        auto& saved = poses[entity.entity];
        const bool retain_team = !entity.team_known && saved.value.team_known &&
            next->captured - saved.team_at < std::chrono::milliseconds(150);
        const bool teammate = saved.value.teammate;
        saved.value = entity;
        saved.captured = next->captured;
        if (entity.team_known)
            saved.team_at = next->captured;
        else if (retain_team) {
            saved.value.team_known = true;
            saved.value.teammate = teammate;
        }
    }

    std::erase_if(
        poses, [&](const auto& item) { return next->captured - item.second.captured >= retention; });
    frame = std::move(next);
    return changed;
}
}
