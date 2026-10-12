#pragma once
#include "sdk/bones.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace base::sdk::skeleton {
struct Point {
    float x{}, y{}, z{};
};

struct Pixel {
    float x{}, y{};
};

struct CircleGeometry {
    Pixel center;
    float radius{};
};

using Matrix = std::array<float, 16>;
using Nodes = std::array<std::optional<Point>, static_cast<unsigned>(Bone::count)>;
inline constexpr unsigned body_bone_count = static_cast<unsigned>(Bone::root) + 1;

class Projection {
    Matrix view_;
    float width_, height_;
    bool valid_;

  public:
    Projection(const Matrix& view, float width, float height) noexcept;
    [[nodiscard]] std::optional<Pixel> Project(Point world) const noexcept;
};

struct PoseKey {
    std::uint32_t name{}, index{};
};

struct Binding {
    std::uint32_t count{};
    std::array<std::optional<std::uint32_t>, static_cast<unsigned>(Bone::count)> indices{};
    bool ambiguous{};
};

inline constexpr std::array<std::array<Bone, 2>, 14> edges{{{Bone::head_joint, Bone::neck_joint},
    {Bone::left_hand, Bone::left_elbow}, {Bone::left_elbow, Bone::left_shoulder},
    {Bone::left_shoulder, Bone::neck_joint}, {Bone::neck_joint, Bone::right_shoulder},
    {Bone::neck_joint, Bone::pelvis}, {Bone::right_shoulder, Bone::right_elbow},
    {Bone::right_elbow, Bone::right_hand}, {Bone::left_foot, Bone::left_knee},
    {Bone::left_knee, Bone::left_hip}, {Bone::left_hip, Bone::pelvis}, {Bone::pelvis, Bone::right_hip},
    {Bone::right_hip, Bone::right_knee}, {Bone::right_knee, Bone::right_foot}}};
inline constexpr std::array<std::array<Bone, 2>, 2> foot_edges{
    {{Bone::left_foot, Bone::left_toe}, {Bone::right_foot, Bone::right_toe}}};
inline constexpr auto finger_edges = [] {
    std::array<std::array<Bone, 2>, 30> result{};
    unsigned edge{};
    for (unsigned side = 0; side < 2; ++side) {
        const auto hand = side ? Bone::right_hand : Bone::left_hand;
        const auto first = static_cast<unsigned>(side ? Bone::right_thumb_1 : Bone::left_thumb_1);
        for (unsigned digit = 0; digit < 5; ++digit) {
            const auto a = static_cast<Bone>(first + digit * 3);
            const auto b = static_cast<Bone>(first + digit * 3 + 1);
            const auto c = static_cast<Bone>(first + digit * 3 + 2);
            result[edge++] = {hand, a};
            result[edge++] = {a, b};
            result[edge++] = {b, c};
        }
    }
    return result;
}();
[[nodiscard]] std::optional<CircleGeometry> HeadCircleGeometry(
    const Nodes& source, const Matrix& view, float width, float height) noexcept;
[[nodiscard]] std::optional<Pixel> Project(
    Point world, const Matrix& view, float width, float height) noexcept;
[[nodiscard]] Point Transform(Point local, const Matrix& world) noexcept;
[[nodiscard]] std::optional<Point> Eye(const Matrix& view) noexcept;
[[nodiscard]] bool CameraAtHead(const Nodes& body, Point camera) noexcept;

[[nodiscard]] std::optional<Binding> Bind(std::span<const PoseKey> keys);
[[nodiscard]] bool Normalize(
    const Binding& records, std::span<const Point> positions, const Matrix& world, Nodes& output) noexcept;
}
