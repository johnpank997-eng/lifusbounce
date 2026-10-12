#pragma once
#include "sdk/player.hpp"
#include <algorithm>
#include <cmath>
#include <optional>

namespace base::sdk::aim {
enum class TargetBone : unsigned { head, closest };

struct Settings {
    bool enabled = false;
    bool show_fov = true;
    float fov = 100.0f;
    float smoothing = 2.0f;
    TargetBone bone = TargetBone::head;
};

struct Target {
    std::uintptr_t entity{};
    skeleton::Pixel position;
};

struct MouseDelta {
    int x{}, y{};

    explicit operator bool() const noexcept { return x != 0 || y != 0; }
};

std::optional<Target> SelectTarget(const Snapshot& frame, const skeleton::Matrix& view, float width,
    float height, const Settings& config, bool team_check, std::uintptr_t locked = 0);

class Controller {
    std::uintptr_t locked_{};
    float fraction_x_{}, fraction_y_{};

  public:
    void Reset() noexcept;

    std::uintptr_t Locked() const noexcept;

    MouseDelta Update(const Snapshot& frame, const skeleton::Matrix& view, float width, float height,
        const Settings& config, bool team_check, bool foreground, bool held, bool menu_open, float elapsed,
        std::chrono::steady_clock::time_point now);
};
}
