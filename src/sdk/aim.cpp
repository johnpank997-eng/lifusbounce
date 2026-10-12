#include "sdk/aim.hpp"

namespace base::sdk::aim {
std::optional<Target> SelectTarget(const Snapshot& frame, const skeleton::Matrix& view, float width,
    float height, const Settings& config, bool team_check, std::uintptr_t locked) {
    if (!frame.local_player || !std::isfinite(config.fov) || config.fov <= 0 || !std::isfinite(width) ||
        !std::isfinite(height) || width <= 0 || height <= 0)
        return std::nullopt;
    if (config.bone != TargetBone::head && config.bone != TargetBone::closest)
        return std::nullopt;
    std::optional<Target> nearest;
    float distance = config.fov;
    for (const auto& entity : frame.entities) {
        if (!entity.entity || entity.entity == frame.local_player ||
            (team_check && (!entity.team_known || entity.teammate)))
            continue;
        std::optional<Target> candidate;
        float candidate_distance = config.fov;
        const unsigned first =
            config.bone == TargetBone::head ? static_cast<unsigned>(skeleton::Bone::head_joint) : 0;
        const unsigned last =
            config.bone == TargetBone::head ? first + 1 : static_cast<unsigned>(skeleton::Bone::root);
        for (unsigned bone = first; bone < last; ++bone) {

            if (bone == static_cast<unsigned>(skeleton::Bone::camera_node))
                continue;
            const auto& point = entity.nodes[bone];
            if (!point)
                continue;
            const auto position = skeleton::Project(*point, view, width, height);
            if (!position || position->x < 0 || position->x > width || position->y < 0 ||
                position->y > height)
                continue;
            const float separation = std::hypot(position->x - width * 0.5f, position->y - height * 0.5f);
            if (!std::isfinite(separation) || separation > candidate_distance)
                continue;
            if (!candidate || separation < candidate_distance) {
                candidate = Target{entity.entity, *position};
                candidate_distance = separation;
            }
        }
        if (!candidate)
            continue;
        if (entity.entity == locked)
            return candidate;
        if (candidate_distance < distance ||
            (candidate_distance == distance && (!nearest || entity.entity < nearest->entity))) {
            nearest = candidate;
            distance = candidate_distance;
        }
    }
    return nearest;
}

auto Controller::Reset() noexcept -> void {
    locked_ = 0;
    fraction_x_ = fraction_y_ = 0;
}

auto Controller::Locked() const noexcept -> std::uintptr_t {
    return locked_;
}

auto Controller::Update(const Snapshot& frame, const skeleton::Matrix& view, float width, float height,
    const Settings& config, bool team_check, bool foreground, bool held, bool menu_open, float elapsed,
    std::chrono::steady_clock::time_point now) -> MouseDelta {
    if (!config.enabled || !foreground || !held || menu_open || now < frame.captured ||
        now - frame.captured > std::chrono::milliseconds(75) || !std::isfinite(elapsed) || elapsed <= 0 ||
        !std::isfinite(config.smoothing)) {
        Reset();
        return {};
    }
    const auto selected = SelectTarget(frame, view, width, height, config, team_check, locked_);
    if (!selected) {
        Reset();
        return {};
    }
    if (locked_ != selected->entity) {
        Reset();
        locked_ = selected->entity;
    }
    const float dx = selected->position.x - width * 0.5f;
    const float dy = selected->position.y - height * 0.5f;
    if (std::hypot(dx, dy) < 1.0f) {
        fraction_x_ = fraction_y_ = 0;
        return {};
    }
    const float smoothing = std::clamp(config.smoothing, 1.0f, 20.0f);
    const float blend = 1.0f - std::exp(-60.0f * std::min(elapsed, 0.05f) / smoothing);
    fraction_x_ += std::clamp(dx * blend, -250.0f, 250.0f);
    fraction_y_ += std::clamp(dy * blend, -250.0f, 250.0f);
    const MouseDelta result{static_cast<int>(fraction_x_), static_cast<int>(fraction_y_)};
    fraction_x_ -= static_cast<float>(result.x);
    fraction_y_ -= static_cast<float>(result.y);
    return result;
}
}
