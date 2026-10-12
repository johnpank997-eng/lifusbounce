#pragma once
#include "ui/overlay.hpp"
#include "core/handle.hpp"
#include "sdk/session.hpp"
#include <imgui.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <string>
#include <unordered_map>

namespace base {
extern float ui_alpha;
float Animate(const char* name, float target, float speed = 14.0f);
bool ToggleRow(const char* label, bool* value, float* color);
void CustomSlider(const char* label, float* value, float v_min, float v_max, float step = 0.1f);
bool ChoiceRow(const char* label, const char* selected, bool dropdown = true);
enum class DebugAction { none, reload, quit };
DebugAction DebugControls();
bool MenuFrame(ImVec2 position, int& selected);
void DrawPlayerStatus(const char* text);

struct Interaction {
    HWND drawing{}, panel{}, game{};
    DWORD game_pid{};
    bool menu = true;
    bool loading = true;
    bool panel_centered = false;
    float panel_x = 0.0f, panel_y = 0.0f;
    mutable float menu_alpha = 0.0f;
    mutable RECT applied{-1, -1, -1, -1};
    mutable std::chrono::steady_clock::time_point last_owned{};
    bool input_active{};
    std::array<bool, 5> mouse_down{}, mouse_owned{};

    bool Owns(HWND window) const;

    bool ForegroundGame() const;

    bool Interactive() const;

    bool ToggleMenu();

    void BeginLoading();

    void UpdateLoading(float progress);

    void ReleaseInput();

    void SyncInput();

    void PollMouse();

    void Hide();
};

struct GameTarget {
    DWORD pid{};
    HWND window{};
    UniqueHandle process;
    bool attached{}, closed{};
    std::chrono::steady_clock::time_point next_search{};
    void Update();
};

struct DisplayPose {
    sdk::Player value;
    float health = std::numeric_limits<float>::quiet_NaN();
    std::chrono::steady_clock::time_point captured{}, team_at{};
};

struct DisplayCache {
    static constexpr auto retention = std::chrono::milliseconds(100);
    std::shared_ptr<const sdk::Snapshot> frame;
    std::unordered_map<std::uintptr_t, DisplayPose> poses;

    void Clear();

    bool Update(std::shared_ptr<const sdk::Snapshot> next);
};

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp);
}
