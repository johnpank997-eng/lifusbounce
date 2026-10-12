#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::IdentifyCameraBody(
    std::optional<skeleton::Point> eye, std::span<const Address> entries, const Environment& env) -> void {
    if (native.local_profile_field) {
        Address owned{}, owned_id{}, owned_profile{};
        bool conflicting{};
        for (const auto entity : entries) {
            const auto found = cache.find(entity);
            if (found == cache.end() || !found->second.transform_component)
                continue;
            auto& c = found->second;
            try {
                const auto profile = ProfileFor(entity, c, env);
                if (!profile || *native.local_profile_field >= Extent(profile, 0x10000) ||
                    Read<std::uint8_t>(profile + *native.local_profile_field) != 1)
                    continue;
                const auto id = Q(entity + 0xb8);

                const auto world = Q(c.transform_component + 0xd0);
                if (!Finite(Read<skeleton::Point>(world + 0x40)))
                    continue;
                if (owned && owned != entity) {
                    owned = 0;
                    conflicting = true;
                    break;
                }
                owned = entity;
                owned_id = id;
                owned_profile = profile;
            } catch (ReadFailure) {
            }
        }
        local_player = owned;
        local_player_id = owned_id;
        if (conflicting) {
            local_profile = 0;
            local_side.reset();
        }
        if (owned)
            local_profile = owned_profile;
        if (local_profile)
            try {
                if (!ValidLocalProfile(local_profile))
                    local_profile = 0;
            } catch (ReadFailure) {
            }
        local_candidate = local_candidate_id = 0;
        local_confirmations = 0;
        return;
    }
    if (local_player) {
        try {
            if (const auto found = cache.find(local_player); found != cache.end()) {
                const auto& c = found->second;

                if (Q(local_player + 0xb8) == local_player_id && Q(local_player) == c.vtable &&
                    Q(local_player + static_cast<Address>(c.component_offset)) == c.list &&
                    (Read<std::uint32_t>(local_player + static_cast<Address>(c.component_offset) + 8) &
                        0x3fffffffu) == c.component_count &&
                    c.local_role && Q(c.list + c.local_role_index * 8ull) == c.local_role &&
                    Hash(c.local_role) == 0xb8f1ea67u)
                    return;
            }
        } catch (ReadFailure) {

            return;
        }
        local_player = 0;
        local_player_id = 0;
        local_candidate = 0;
        local_candidate_id = 0;
        local_confirmations = 0;
    }
    Address selected_local{}, selected_id{};
    float nearest = 1.0f;
    if (!eye)
        return;
    for (const auto entity : entries) {
        const auto found = cache.find(entity);
        if (found == cache.end())
            continue;
        const auto& c = found->second;
        if (!c.local_role || !c.transform_component)
            continue;
        try {
            const auto id = Q(entity + 0xb8);
            if (((id >> 24) & 0xff) == 0xfa || ((id >> 32) & 0xff) != 0)
                continue;
            if (Q(entity) != c.vtable || Q(entity + static_cast<Address>(c.component_offset)) != c.list ||
                (Read<std::uint32_t>(entity + static_cast<Address>(c.component_offset) + 8) & 0x3fffffffu) !=
                    c.component_count ||
                Q(c.list + c.local_role_index * 8ull) != c.local_role || Hash(c.local_role) != 0xb8f1ea67u ||
                Q(c.list + c.transform_index * 8ull) != c.transform_component ||
                Hash(c.transform_component) != 0x1d26c443u)
                continue;
            const auto world = Q(c.transform_component + 0xd0);
            const auto origin = Read<skeleton::Point>(world + 0x40);
            const auto distance = std::hypot(origin.x - eye->x, origin.y - eye->y);
            if (!Finite(origin) || !std::isfinite(distance) || distance >= nearest)
                continue;
            nearest = distance;
            selected_local = entity;
            selected_id = id;
        } catch (ReadFailure) {
        }
    }
    if (!selected_local) {
        local_candidate = 0;
        local_candidate_id = 0;
        local_confirmations = 0;
        return;
    }
    if (selected_local != local_candidate || selected_id != local_candidate_id) {
        local_candidate = selected_local;
        local_candidate_id = selected_id;
        local_confirmations = 0;
    }
    if (++local_confirmations >= 3) {
        local_player = selected_local;
        local_player_id = selected_id;
    }
}
}
