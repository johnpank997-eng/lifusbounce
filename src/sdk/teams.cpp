#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::ClearTeam(CachedEntity& c) -> void {
    c.team_parent = c.team_list = c.team_component = c.team_field = 0;
    c.team_list_offset = c.team_source_field = 0;
    c.team_count = c.team_index = 0;
    c.team = 0;
    c.team_at = {};
    c.next_team_attempt = {};
}

auto Reader::Implementation::DiscoverTeam(CachedEntity& c) -> void {

    constexpr Address source_field = 0x48;
    if (source_field + 8 > Extent(c.team_source, 0x2000))
        throw ReadFailure{ERROR_INVALID_DATA};
    const auto parent = Q(c.team_source + source_field);
    const auto bytes = Array<std::byte>(parent, static_cast<std::size_t>(Extent(parent, 0x2000)));

    struct TeamBinding {
        Address list{}, component{}, field{}, list_field{}, owner{};
        std::uint32_t count{}, index{};
    } accepted;

    for (std::size_t i = 0; i + 16 <= bytes.size(); i += 8) {
        Address list{}, flags{};
        std::memcpy(&list, bytes.data() + i, 8);
        std::memcpy(&flags, bytes.data() + i + 8, 8);
        const auto count = static_cast<std::uint32_t>(flags & 0x3fffffffull);
        if (!count || count >= 20 || !Pointer(list))
            continue;
        try {
            const auto components = Array<Address>(list, count);
            for (std::uint32_t index = 0; index < count; ++index) {
                const auto component = components[index];
                try {
                    if (Hash(component) != 0xd2305a06u)
                        continue;
                    const auto fields =
                        Array<std::byte>(component, static_cast<std::size_t>(Extent(component, 0x10000)));
                    for (std::size_t field = 0; field + 8 <= fields.size(); field += 8) {
                        Address slot{};
                        std::memcpy(&slot, fields.data() + field, 8);
                        try {
                            const auto owner = Q(slot);
                            if (Hash(owner) != 0xadeca645u)
                                continue;

                            if (accepted.owner &&
                                (accepted.owner != owner || accepted.component != component))
                                throw ReadFailure{ERROR_DUP_NAME};
                            if (!accepted.owner)
                                accepted = {list, component, field, i, owner, count, index};
                        } catch (ReadFailure failure) {
                            if (failure.error == ERROR_DUP_NAME)
                                throw;
                        }
                    }
                } catch (ReadFailure failure) {
                    if (failure.error == ERROR_DUP_NAME)
                        throw;
                }
            }
        } catch (ReadFailure failure) {
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    }
    if (accepted.owner) {
        if (Q(c.team_source + source_field) != parent)
            throw ReadFailure{ERROR_NOT_READY};
        c.team_parent = parent;
        c.team_list = accepted.list;
        c.team_component = accepted.component;
        c.team_field = accepted.field;
        c.team_list_offset = accepted.list_field;
        c.team_source_field = source_field;
        c.team_count = accepted.count;
        c.team_index = accepted.index;
    }
}

auto Reader::Implementation::SideFor(Address entity, CachedEntity& c) -> Address {
    FeatureEvidence evidence{.entity = entity, .receiver = c.team_source};
    auto stage = FeatureStage::component;
    const auto record = [&](FeatureStatus status) {
        feature_trace.Record(Feature::team, stage, status, evidence);
    };
    if (!c.team_source) {
        record(FeatureStatus::missing_component);
        ClearTeam(c);
        return 0;
    }
    const auto now = std::chrono::steady_clock::now();
    try {
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
            Q(c.list + c.team_source_index * 8ull) != c.team_source || Hash(c.team_source) != 0xcdfd8752u) {
            record(FeatureStatus::state_changed);
            ClearTeam(c);
            c.team_source = 0;
            c.next_components = {};
            return 0;
        }

        if (c.team_component &&
            (Q(c.team_source + c.team_source_field) != c.team_parent ||
                Q(c.team_parent + c.team_list_offset) != c.team_list ||
                (Read<std::uint32_t>(c.team_parent + c.team_list_offset + 8) & 0x3fffffffu) != c.team_count ||
                Q(c.team_list + c.team_index * 8ull) != c.team_component ||
                Hash(c.team_component) != 0xd2305a06u))
            ClearTeam(c);
        if (!c.team_component && now >= c.next_team_attempt) {
            stage = FeatureStage::discovery;
            c.next_team_attempt = now + std::chrono::milliseconds(100);
            DiscoverTeam(c);
        }
        if (!c.team_component) {
            record(FeatureStatus::missing_path);
            return 0;
        }
        stage = FeatureStage::value;
        evidence.receiver = c.team_component;
        evidence.parent = c.team_parent;
        evidence.field = c.team_field;
        const auto slot = Q(c.team_component + c.team_field);
        const auto team = Q(slot);
        evidence.value = team;
        evidence.expected = 0xadeca645u;
        evidence.observed = Hash(team);
        if (evidence.observed != evidence.expected) {
            record(FeatureStatus::type_rejected);
            ClearTeam(c);
            return 0;
        }
        stage = FeatureStage::snapshot;
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
            Q(c.list + c.team_source_index * 8ull) != c.team_source ||
            Q(c.team_source + c.team_source_field) != c.team_parent ||
            Q(c.team_parent + c.team_list_offset) != c.team_list ||
            (Read<std::uint32_t>(c.team_parent + c.team_list_offset + 8) & 0x3fffffffu) != c.team_count ||
            Q(c.team_list + c.team_index * 8ull) != c.team_component ||
            Q(c.team_component + c.team_field) != slot || Q(slot) != team)
            throw ReadFailure{ERROR_NOT_READY};
        c.team = team;
        c.team_at = now;
        record(FeatureStatus::ready);
        return team;
    } catch (ReadFailure failure) {
        evidence.win32 = failure.error;
        record(failure.error == ERROR_DUP_NAME     ? FeatureStatus::ambiguous_path
                : failure.error == ERROR_NOT_READY ? FeatureStatus::state_changed
                                                   : FeatureStatus::read_failed);

        ClearTeam(c);
        c.next_team_attempt = now + std::chrono::milliseconds(100);
        return 0;
    }
}

auto Reader::Implementation::AffiliationFor(
    Address profile, std::optional<std::size_t>& binding, const Environment& env) -> Address {
    Address accepted{};
    FeatureEvidence evidence{.receiver = profile};
    const auto record = [&](FeatureStatus status) {
        feature_trace.Record(Feature::team, FeatureStage::affiliation, status, evidence);
    };
    try {
        if (!profile) {
            record(FeatureStatus::uninitialized);
            return 0;
        }
        if (native.affiliations.empty())
            record(FeatureStatus::missing_path);
        std::optional<std::size_t> matched;
        for (std::size_t i = 0; i < native.affiliations.size(); ++i) {
            if (binding && *binding != i)
                continue;
            const auto& path = native.affiliations[i];
            evidence.path = i;
            evidence.field = path.field;
            evidence.extent = Extent(profile, 0x10000);
            if (path.field + 8 > evidence.extent) {
                record(FeatureStatus::extent_rejected);
                continue;
            }
            const auto encoded = Q(profile + path.field);
            cpu.Reset(env.teb);
            cpu.Set(path.profile, profile);
            if (!trace.Run(cpu, path.object.code, "team_affiliation", i, module.address)) {
                record(FeatureStatus::emulation_failed);
                continue;
            }
            const auto team = cpu.Get(path.object.output);
            evidence.value = team;
            evidence.expected = path.null_value;
            if (team == path.null_value || !team) {
                record(FeatureStatus::uninitialized);
                continue;
            }
            if (path.pointer_identity) {
                if (!Pointer(team)) {
                    record(FeatureStatus::invalid_value);
                    continue;
                }
                TypeInfo(team);
            }
            if (Q(profile + path.field) != encoded) {
                record(FeatureStatus::state_changed);
                continue;
            }
            if (accepted && accepted != team) {
                record(FeatureStatus::ambiguous_path);
                return 0;
            }
            accepted = team;
            if (!matched)
                matched = i;
        }
        binding = matched;
        if (accepted)
            record(FeatureStatus::ready);
        return accepted;
    } catch (ReadFailure failure) {
        evidence.win32 = failure.error;
        record(FeatureStatus::read_failed);
        return 0;
    }
}

auto Reader::Implementation::TeamFor(Address entity, CachedEntity& c, const Environment& env) -> Address {
    const auto side = SideFor(entity, c);
    if (!side && c.team_source)
        feature_trace.Receiver(process, module, sections, native.metadata, Feature::team,
            FeatureStage::component, 0, env.teb, entity, c.team_source);
    return side;
}

auto Reader::Implementation::ValidLocalProfile(Address profile) -> bool {
    if (!profile || !native.local_profile_field || native.usernames.size() != 1 ||
        *native.local_profile_field >= Extent(profile, 0x10000))
        return false;
    const auto range = Read<std::array<std::uint16_t, 2>>(TypeInfo(profile) + 0x40);
    const auto expected = Read<std::array<std::uint16_t, 2>>(native.usernames.front().profile_type);
    return range[0] >= expected[0] && range[1] <= expected[1] &&
        Read<std::uint8_t>(profile + *native.local_profile_field) == 1;
}

auto Reader::Implementation::LocalTeamFor(const Environment& env) -> Address {
    Address current{};
    if (const auto local = cache.find(local_player); local != cache.end())
        current = TeamFor(local_player, local->second, env);
    try {
        if (current) {

            if (!ValidLocalProfile(local_profile)) {
                local_side.reset();
                return current;
            }
            const auto table = Q(local_profile);
            const auto side_table = Q(current);
            const auto affiliation = AffiliationFor(local_profile, local_affiliation_path, env);
            if (!affiliation || !ValidLocalProfile(local_profile) || Q(local_profile) != table ||
                Q(current) != side_table || Hash(current) != 0xadeca645u) {
                local_side.reset();
                return current;
            }
            local_side =
                LocalSideBinding{local_profile, table, affiliation, current, side_table, env.manager};
            return current;
        }

        if (local_player)
            return 0;
        if (!local_side)
            return 0;
        const auto& saved = *local_side;
        if (saved.manager != env.manager || local_profile != saved.profile ||
            !ValidLocalProfile(saved.profile) || Q(saved.profile) != saved.profile_vtable ||
            Hash(saved.side) != 0xadeca645u || Q(saved.side) != saved.side_vtable ||
            AffiliationFor(saved.profile, local_affiliation_path, env) != saved.affiliation ||
            !ValidLocalProfile(saved.profile) || Q(saved.profile) != saved.profile_vtable ||
            Q(saved.side) != saved.side_vtable) {
            local_side.reset();
            return 0;
        }
        return saved.side;
    } catch (ReadFailure) {

        return 0;
    }
}
}
