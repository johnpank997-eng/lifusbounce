#include "sdk/skeleton.hpp"
#include <algorithm>
#include <cmath>

namespace base::sdk::skeleton {
namespace {
bool Finite(Point p) {
    return std::isfinite(p.x) && std::isfinite(p.y) && std::isfinite(p.z);
}

std::optional<Pixel> ProjectPoint(Point p, const Matrix& m, float width, float height) noexcept {
    if (!Finite(p))
        return std::nullopt;
    const float x = p.x * m[0] + p.y * m[4] + p.z * m[8] + m[12];
    const float y = p.x * m[1] + p.y * m[5] + p.z * m[9] + m[13];
    const float w = p.x * m[3] + p.y * m[7] + p.z * m[11] + m[15];
    if (!std::isfinite(w) || w < 0.1f)
        return std::nullopt;
    const Pixel result{(x / w + 1.0f) * width * 0.5f, (1.0f - y / w) * height * 0.5f};
    if (!std::isfinite(result.x) || !std::isfinite(result.y))
        return std::nullopt;
    return result;
}
}

Projection::Projection(const Matrix& view, float width, float height) noexcept
    : view_(view), width_(width), height_(height),
      valid_(std::isfinite(width) && std::isfinite(height) && width > 0 && height > 0 &&
          std::all_of(view.begin(), view.end(), [](float value) { return std::isfinite(value); })) {}

std::optional<Pixel> Projection::Project(Point p) const noexcept {
    return valid_ ? ProjectPoint(p, view_, width_, height_) : std::nullopt;
}

std::optional<Pixel> Project(Point p, const Matrix& m, float width, float height) noexcept {
    if (!std::isfinite(width) || !std::isfinite(height) || width <= 0 || height <= 0 ||
        !std::all_of(m.begin(), m.end(), [](float value) { return std::isfinite(value); }))
        return std::nullopt;
    return ProjectPoint(p, m, width, height);
}

Point Transform(Point p, const Matrix& m) noexcept {
    return {p.x * m[0] + p.y * m[4] + p.z * m[8] + m[12], p.x * m[1] + p.y * m[5] + p.z * m[9] + m[13],
        p.x * m[2] + p.y * m[6] + p.z * m[10] + m[14]};
}

std::optional<Point> Eye(const Matrix& m) noexcept {
    using Vector = std::array<double, 3>;
    const Vector right{m[0], m[4], m[8]}, up{m[1], m[5], m[9]}, forward{m[3], m[7], m[11]};
    const auto cross = [](const Vector& a, const Vector& b) {
        return Vector{a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]};
    };
    const auto a = cross(up, forward), b = cross(forward, right), c = cross(right, up);
    const auto determinant = right[0] * a[0] + right[1] * a[1] + right[2] * a[2];
    if (!std::isfinite(determinant) || determinant == 0)
        return std::nullopt;
    Point result{};
    std::array<float*, 3> components{&result.x, &result.y, &result.z};
    for (unsigned j = 0; j < 3; ++j)
        *components[j] = static_cast<float>((-m[12] * a[j] - m[13] * b[j] - m[15] * c[j]) / determinant);
    return Finite(result) ? std::optional<Point>(result) : std::nullopt;
}

bool CameraAtHead(const Nodes& body, Point camera) noexcept {
    const auto& head = body[static_cast<unsigned>(Bone::camera_node)];

    return head && Finite(*head) && Finite(camera) &&
        std::hypot(head->x - camera.x, head->y - camera.y, head->z - camera.z) <= 0.35f;
}

std::optional<CircleGeometry> HeadCircleGeometry(
    const Nodes& source, const Matrix& view, float width, float height) noexcept {
    const auto& head = source[static_cast<unsigned>(Bone::head_joint)];
    if (!head)
        return std::nullopt;
    const auto center = Project(*head, view, width, height);
    if (!center)
        return std::nullopt;

    constexpr float world_radius = 0.10f;
    const float depth = head->x * view[3] + head->y * view[7] + head->z * view[11] + view[15];
    const float focal_scale = std::hypot(view[1], view[5], view[9]);
    const float radius = world_radius * focal_scale * height * 0.5f / depth;
    if (!std::isfinite(radius) || radius <= 0.0f)
        return std::nullopt;
    return CircleGeometry{*center, radius};
}

std::optional<Binding> Bind(std::span<const PoseKey> keys) {
    constexpr std::array names{BoneHash::pelvis, BoneHash::stomach, BoneHash::lumbar, BoneHash::thorax,
        BoneHash::spine, BoneHash::neck, BoneHash::left_hip, BoneHash::left_knee, BoneHash::left_foot,
        BoneHash::left_toe, BoneHash::left_clavicle, BoneHash::left_shoulder, BoneHash::left_elbow,
        BoneHash::left_hand, BoneHash::right_hip, BoneHash::right_knee, BoneHash::right_foot,
        BoneHash::right_toe, BoneHash::right_clavicle, BoneHash::right_shoulder, BoneHash::right_elbow,
        BoneHash::right_hand, BoneHash::head, BoneHash::root, BoneHash::left_thumb_1, BoneHash::left_thumb_2,
        BoneHash::left_thumb_3, BoneHash::left_index_1, BoneHash::left_index_2, BoneHash::left_index_3,
        BoneHash::left_middle_1, BoneHash::left_middle_2, BoneHash::left_middle_3, BoneHash::left_ring_1,
        BoneHash::left_ring_2, BoneHash::left_ring_3, BoneHash::left_pinky_1, BoneHash::left_pinky_2,
        BoneHash::left_pinky_3, BoneHash::right_thumb_1, BoneHash::right_thumb_2, BoneHash::right_thumb_3,
        BoneHash::right_index_1, BoneHash::right_index_2, BoneHash::right_index_3, BoneHash::right_middle_1,
        BoneHash::right_middle_2, BoneHash::right_middle_3, BoneHash::right_ring_1, BoneHash::right_ring_2,
        BoneHash::right_ring_3, BoneHash::right_pinky_1, BoneHash::right_pinky_2, BoneHash::right_pinky_3};
    static_assert(names.size() == static_cast<unsigned>(Bone::count));
    Binding result{};
    std::array<bool, static_cast<unsigned>(Bone::count)> duplicates{};
    for (std::uint32_t i = 0; i < keys.size(); ++i) {
        const auto name = keys[i].name, index = keys[i].index;
        if (index >= 4096)
            return std::nullopt;
        result.count = std::max(result.count, index + 1);
        if (!name)
            continue;
        const auto found = std::find(names.begin(), names.end(), static_cast<BoneHash>(name));
        if (found == names.end())
            continue;
        const auto id = static_cast<std::size_t>(found - names.begin());
        if (duplicates[id])
            continue;
        if (result.indices[id] && *result.indices[id] != index) {
            result.indices[id].reset();
            duplicates[id] = true;
            result.ambiguous |= id < body_bone_count;
        } else
            result.indices[id] = index;
    }
    if (!result.ambiguous &&
        std::none_of(result.indices.begin(), result.indices.begin() + body_bone_count,
            [](auto i) { return i.has_value(); }))
        return std::nullopt;
    return result;
}

bool Normalize(
    const Binding& records, std::span<const Point> positions, const Matrix& world, Nodes& output) noexcept {
    output = {};
    if (positions.size() != records.count ||
        !std::all_of(world.begin(), world.end(), [](float v) { return std::isfinite(v); }))
        return false;
    Nodes result{};
    for (unsigned id = 0; id < records.indices.size(); ++id)
        if (auto i = records.indices[id]) {
            if (*i >= positions.size())
                return false;
            auto p = Transform(positions[*i], world);
            if (!Finite(p)) {
                if (id < body_bone_count)
                    return false;
                continue;
            }
            result[id] = p;
        }
    output = result;
    return true;
}
}
