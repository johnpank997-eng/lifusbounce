#include "sdk/reader_internal.hpp"
#include "core/diagnostics.hpp"

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
            if (!trace.Run(cpu, path.owner.code, "rig_emulation_failed", i, module.address))
                continue;
            const auto rig = cpu.Get(path.owner.output);
            if (Hash(rig) != 0x4da91c62u) {
                trace.Count("rig_type_rejected");
                continue;
            }
            const auto names = Q(rig + path.names_field);
            const auto count = static_cast<std::uint32_t>(
                (path.count_width == 64 ? Q(rig + path.names_field + 8)
                                        : Read<std::uint32_t>(rig + path.names_field + 8)) &
                0x3fffffffu);
            if (!count || count > 4096 || !Pointer(names)) {
                trace.Count("rig_names_or_count_rejected");
                continue;
            }
            if (matched && (value.rig != rig || value.names != names || value.count != count))
                throw ReadFailure{ERROR_DUP_NAME};
            value.rig = rig;
            value.names = names;
            value.count = count;
            if (!matched)
                matched = i;
        } catch (ReadFailure failure) {
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    if (!matched) {
        trace.Count("rig_not_resolved");
        throw ReadFailure{ERROR_NOT_READY};
    }
    c.rig_path = matched;
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
            const auto asset = Evaluate(path.asset, env.teb, c.animation_component, "pose_asset", i);
            if (!Pointer(asset)) {
                trace.Count("pose_asset_rejected");
                continue;
            }
            const auto buffer = Evaluate(path.buffer, env.teb, asset, "pose_buffer", i);
            if (!Pointer(buffer)) {
                trace.Count("pose_buffer_rejected");
                continue;
            }
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
    if (!matched) {
        trace.Count("pose_not_resolved");
        throw ReadFailure{ERROR_NOT_READY};
    }
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

    struct RigName {
        std::uint32_t hash{};
        std::uint16_t index{}, reserved{};
        bool operator==(const RigName&) const = default;
    };

    const auto rig_names = Array<RigName>(names, count);
    const bool sample = diagnostics::Enabled() && sampled_skeletons.size() < 32 &&
        sampled_skeletons.insert(c.animation_component).second;
    const auto save_names = [&] {
        if (!sample)
            return;
        diagnostics::Write("skeleton_evidence",
            {{"animation", diagnostics::Hex(c.animation_component)}, {"rig", diagnostics::Hex(animation.rig)},
                {"names", diagnostics::Hex(names)}, {"asset", diagnostics::Hex(animation.asset)},
                {"buffer", diagnostics::Hex(animation.buffer)}, {"count", count},
                {"name_record_size", sizeof(RigName)}, {"pose_stride", pose_stride},
                {"names_sha256", diagnostics::Sha256(std::as_bytes(std::span(rig_names)))}});
        diagnostics::Artifact("rig_names", 0, std::as_bytes(std::span(rig_names)));
    };
    std::vector<skeleton::PoseKey> keys;
    keys.reserve(count);
    for (const auto& name : rig_names) {
        if (name.index >= count) {
            trace.Count("native_bone_index_out_of_bounds");
            save_names();
            return std::nullopt;
        }
        keys.push_back({name.hash, name.index});
    }
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
    if (!c.binding) {
        trace.Count("required_bone_names_missing");
        save_names();
        return std::nullopt;
    }
    if (c.binding->ambiguous) {
        ++ambiguous_bones;
        trace.Count("bone_binding_ambiguous");
        save_names();
        return std::nullopt;
    }
    const auto world = Q(c.transform_component + 0xd0);
    const auto world_transform = Read<skeleton::Matrix>(world + 0x10);
    const auto poses = Array<std::byte>(animation.buffer, count * pose_stride);
    const auto save_pose = [&] {
        save_names();
        if (!sample)
            return;
        diagnostics::Artifact("pose_values", 0, poses);
        diagnostics::Artifact("world_matrix", 0, std::as_bytes(std::span(&world_transform, 1)));
    };
    const auto after = AnimationFor(c, env);

    if (after.rig != animation.rig || after.names != names || after.count != count ||
        after.asset != animation.asset || after.buffer != animation.buffer ||
        Q(c.transform_component + 0xd0) != world || Read<skeleton::Matrix>(world + 0x10) != world_transform ||
        Array<RigName>(names, count) != rig_names) {
        trace.Count("skeleton_graph_changed_during_read");
        save_pose();
        return std::nullopt;
    }
    const auto confirmed = Array<std::byte>(animation.buffer, count * pose_stride);
    std::vector<skeleton::Point> points(count);
    for (const auto index : c.binding->indices)
        if (index) {
            const auto offset = *index * pose_stride;
            if (std::memcmp(poses.data() + offset, confirmed.data() + offset, sizeof(skeleton::Point))) {
                trace.Count("pose_changed_during_read");
                save_pose();
                return std::nullopt;
            }
            std::memcpy(&points[*index], poses.data() + offset, sizeof(skeleton::Point));
        }
    skeleton::Nodes nodes{};
    if (!skeleton::Normalize(*c.binding, points, world_transform, nodes)) {
        ++invalid_poses;
        trace.Count("pose_normalization_rejected");
        save_pose();
        return std::nullopt;
    }
    const skeleton::Point translation{world_transform[12], world_transform[13], world_transform[14]};
    save_pose();
    return Actor{entity, translation, std::move(nodes)};
}
}
