#pragma once
#include <chrono>

namespace base {
inline std::chrono::steady_clock::time_point FrameDeadline(std::chrono::steady_clock::time_point started,
    std::chrono::steady_clock::time_point finished, std::chrono::steady_clock::duration interval) noexcept {
    const auto scheduled = started + interval;
    return scheduled > finished ? scheduled : finished;
}
}
