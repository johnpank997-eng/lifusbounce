#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::RigFor(CachedEntity& c) -> AnimationView {
    AnimationView value{};
    std::optional<std::size_t> matched;
    for (std::size_t i = 0; i < native.rigs.size(); ++i)
        try {
            if (c.rig_path && i != *c.rig_path)
                continue;
            const auto& path = native.rigs[i];
            cpu.Reset();
            cpu.Set(ZYDIS_REGISTER_RCX, c.animation_component);
            if (!cpu.Run(path.code).Complete())
                continue;
            const auto rig = cpu.Get(path.output);
            if (Hash(rig) != 0x4da91c62u)
                continue;
            if (matched && value.rig != rig)
                throw ReadFailure{ERROR_DUP_NAME};
            value.rig = rig;
            if (!matched)
                matched = i;
        } catch (ReadFailure failure) {
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    if (!matched)
        throw ReadFailure{ERROR_NOT_READY};
    c.rig_path = matched;
    value.names = Q(value.rig + names_field);
    value.count = Read<std::uint32_t>(value.rig + names_field + 8) & 0x3fffffffu;
    if (!value.count || value.count > 4096 || !Pointer(value.names))
        throw ReadFailure{ERROR_INVALID_DATA};
    return value;
}

auto Reader::Implementation::AnimationFor(CachedEntity& c, const Environment& env) -> AnimationView {
    auto result = RigFor(c);
    std::optional<std::size_t> matched;

    for (std::size_t i = 0; i < native.poses.size(); ++i)
        try {
            if (c.pose_path && i != *c.pose_path)
                continue;
            const auto& path = native.poses[i];
            const auto asset = Evaluate(path.asset, env.teb, c.animation_component);
            if (!Pointer(asset))
                continue;
            const auto buffer = Evaluate(path.buffer, env.teb, asset);
            if (!Pointer(buffer))
                continue;
            if (matched && (result.asset != asset || result.buffer != buffer))
                throw ReadFailure{ERROR_DUP_NAME};
            result.asset = asset;
            result.buffer = buffer;
            if (!matched)
                matched = i;
        } catch (ReadFailure failure) {
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    if (!matched)
        throw ReadFailure{ERROR_NOT_READY};
    c.pose_path = matched;
    emulation_error.reset();
    return result;
}

auto Reader::Implementation::SkeletonFor(Address entity, const Environment& env) -> std::optional<Actor> {
    const auto found = cache.find(entity);
    if (found == cache.end())
        return std::nullopt;
    auto& c = found->second;
    if (!c.animation_component || !c.transform_component)
        return std::nullopt;
    if (Q(entity) != c.vtable || Q(entity + static_cast<Address>(c.component_offset)) != c.list ||
        (Read<std::uint32_t>(entity + static_cast<Address>(c.component_offset) + 8) & 0x3fffffffu) !=
            c.component_count ||
        Q(c.list + c.animation_index * 8ull) != c.animation_component ||
        Q(c.list + c.transform_index * 8ull) != c.transform_component ||
        Hash(c.animation_component) != 0x4e4b0976u || Hash(c.transform_component) != 0x1d26c443u) {
        c = Discover(entity);
        if (!c.animation_component || !c.transform_component)
            return std::nullopt;
    }

    for (unsigned attempt = 0; attempt < 3; ++attempt)
        try {
            if (auto pose = CaptureSkeleton(entity, c, env))
                return pose;
        } catch (ReadFailure) {
            if (attempt == 2)
                throw;
        }
    return std::nullopt;
}

auto Reader::Implementation::CaptureSkeleton(Address entity, CachedEntity& c, const Environment& env)
    -> std::optional<Actor> {
    const auto animation = AnimationFor(c, env);
    const auto count = animation.count;
    if (!count || count > 4096)
        return std::nullopt;
    const auto names = animation.names;
    const auto rig_names = Array<std::uint32_t>(names, count);
    std::vector<skeleton::PoseKey> keys;
    keys.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i)
        keys.push_back({rig_names[i], i});
    const bool rig_changed = c.rig != animation.rig || c.names != names || c.pose_count != count ||
        c.keys.size() != keys.size() ||
        !std::equal(c.keys.begin(), c.keys.end(), keys.begin(),
            [](const auto& a, const auto& b) { return a.name == b.name && a.index == b.index; });
    if (rig_changed) {
        c.rig = animation.rig;
        c.names = names;
        c.pose_count = count;
        c.keys = std::move(keys);
        c.binding = skeleton::Bind(c.keys);
    }
    if (!c.binding)
        return std::nullopt;
    if (c.binding->ambiguous) {
        ++ambiguous_bones;
        return std::nullopt;
    }
    const auto world = Q(c.transform_component + 0xd0);
    const auto world_transform = Read<skeleton::Matrix>(world + 0x10);
    const auto poses = Array<std::byte>(animation.buffer, count * pose_stride);
    const auto after = AnimationFor(c, env);

    if (after.rig != animation.rig || after.names != names || after.count != count ||
        after.asset != animation.asset || after.buffer != animation.buffer ||
        Q(c.transform_component + 0xd0) != world || Read<skeleton::Matrix>(world + 0x10) != world_transform ||
        Array<std::uint32_t>(names, count) != rig_names)
        return std::nullopt;
    const auto confirmed = Array<std::byte>(animation.buffer, count * pose_stride);
    std::vector<skeleton::Point> points(count);
    for (const auto index : c.binding->indices)
        if (index) {
            const auto offset = *index * pose_stride;
            if (std::memcmp(poses.data() + offset, confirmed.data() + offset, sizeof(skeleton::Point)))
                return std::nullopt;
            std::memcpy(&points[*index], poses.data() + offset, sizeof(skeleton::Point));
        }
    skeleton::Nodes nodes{};
    if (!skeleton::Normalize(*c.binding, points, world_transform, nodes)) {
        ++invalid_poses;
        return std::nullopt;
    }
    const skeleton::Point translation{world_transform[12], world_transform[13], world_transform[14]};
    return Actor{entity, translation, std::move(nodes)};
}
}
