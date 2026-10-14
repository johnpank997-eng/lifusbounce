#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::ProfileFor(Address entity, CachedEntity& c, const Environment& env) -> Address {
    FeatureEvidence evidence{.entity = entity, .receiver = c.username_component};
    auto stage = FeatureStage::discovery;
    const auto record = [&](FeatureStatus status) {
        if (status != FeatureStatus::ready && status != FeatureStatus::cached) {
            c.profile = c.name_profile = 0;
            c.username.clear();
        }
        feature_trace.Record(Feature::name, stage, status, evidence);
    };
    if (!c.username_component || native.usernames.size() != 1) {
        c.profile = c.name_profile = 0;
        c.username.clear();
        feature_trace.Record(Feature::name, FeatureStage::discovery,
            !c.username_component          ? FeatureStatus::missing_component
                : native.usernames.empty() ? FeatureStatus::missing_path
                                           : FeatureStatus::ambiguous_path,
            {.entity = entity, .receiver = c.username_component, .value = native.usernames.size()});
        if (c.username_component)
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::name,
                FeatureStage::discovery, 0, env.teb, entity, c.username_component);
        return 0;
    }
    const auto stable_component = [&] {
        return c.component_count && c.username_index < c.component_count && Q(entity) == c.vtable &&
            Q(entity + c.component_offset) == c.list &&
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) == c.component_count &&
            Q(c.list + c.username_index * 8ull) == c.username_component &&
            Hash(c.username_component) == 0xd1d46a6fu;
    };
    try {
        stage = FeatureStage::component;
        if (!stable_component()) {
            c.username_component = c.name_profile = c.profile = 0;
            c.username.clear();
            c.affiliation_path.reset();
            c.next_components = {};
            record(FeatureStatus::state_changed);
            return 0;
        }
        const auto now = std::chrono::steady_clock::now();
        if (c.profile && now - c.profile_at < std::chrono::milliseconds(30)) {
            evidence.receiver = c.profile;
            stage = FeatureStage::profile;
            record(FeatureStatus::cached);
            return c.profile;
        }
        c.profile = 0;
        const auto& path = native.usernames.front();
        const auto matches = [&](Address object, Address expected) {
            const auto range = Read<std::array<std::uint16_t, 2>>(TypeInfo(object) + 0x40);
            const auto base = Read<std::array<std::uint16_t, 2>>(expected);
            evidence.receiver = object;
            evidence.address = expected;
            evidence.expected = base[0] | (static_cast<std::uint64_t>(base[1]) << 16);
            evidence.observed = range[0] | (static_cast<std::uint64_t>(range[1]) << 16);
            return range[0] >= base[0] && range[1] <= base[1];
        };
        stage = FeatureStage::owner;
        cpu.Reset(env.teb);
        cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
        if (!trace.Run(cpu, path.owner.code, "name_owner_emulation_failed", 0, module.address)) {
            record(FeatureStatus::emulation_failed);
            return 0;
        }
        const auto owner = cpu.Get(path.owner.output);
        if (!Pointer(owner)) {
            evidence.receiver = owner;
            record(owner ? FeatureStatus::invalid_value : FeatureStatus::uninitialized);
            return 0;
        }
        if (Hash(owner) == 0xc812b23du) {
            stage = FeatureStage::profile;
            cpu.Reset(env.teb);
            cpu.Set(path.owner.output, owner);
            if (!trace.Run(cpu, path.profile.code, "name_profile_emulation_failed", 0, module.address)) {
                record(FeatureStatus::emulation_failed);
                return 0;
            }
            const auto profile = cpu.Get(path.profile.output);
            evidence.receiver = profile;
            if (!Pointer(profile) || Hash(profile) != 0x5d19580bu) {
                record(FeatureStatus::type_rejected);
                return 0;
            }
            if (!stable_component()) {
                record(FeatureStatus::state_changed);
                return 0;
            }
            c.profile = 0;
            if (c.name_profile != profile) {
                c.name_profile = 0;
                c.username.clear();
            }
            feature_trace.Record(Feature::name, stage, FeatureStatus::unavailable,
                {.entity = entity,
                    .receiver = profile,
                    .expected = path.profile_type,
                    .observed = 0x5d19580bu});
            return 0;
        }
        if (!matches(owner, path.owner_type)) {
            record(FeatureStatus::type_rejected);
            return 0;
        }
        stage = FeatureStage::profile;
        cpu.Reset(env.teb);
        cpu.Set(path.owner.output, owner);
        if (!trace.Run(cpu, path.profile.code, "name_profile_emulation_failed", 0, module.address)) {
            evidence.receiver = owner;
            record(FeatureStatus::emulation_failed);
            return 0;
        }
        const auto profile = cpu.Get(path.profile.output);
        if (!Pointer(profile)) {
            evidence.receiver = profile;
            record(profile ? FeatureStatus::invalid_value : FeatureStatus::uninitialized);
            return 0;
        }
        if (!matches(profile, path.profile_type)) {
            record(FeatureStatus::type_rejected);
            return 0;
        }
        stage = FeatureStage::snapshot;
        if (!stable_component()) {
            record(FeatureStatus::state_changed);
            return 0;
        }
        c.profile = profile;
        c.profile_at = now;
        record(FeatureStatus::ready);
        return profile;
    } catch (ReadFailure failure) {
        c.profile = 0;
        evidence.win32 = failure.error;
        record(FeatureStatus::read_failed);
        return 0;
    }
}

auto Reader::Implementation::UsernameFor(Address entity, CachedEntity& c, const Environment& env)
    -> std::string {
    if (!c.username_component || native.usernames.size() != 1) {
        c.username.clear();
        c.name_profile = 0;
        feature_trace.Record(Feature::name, FeatureStage::discovery,
            !c.username_component          ? FeatureStatus::missing_component
                : native.usernames.empty() ? FeatureStatus::missing_path
                                           : FeatureStatus::ambiguous_path,
            {.entity = entity, .receiver = c.username_component, .value = native.usernames.size()});
        if (c.username_component)
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::name,
                FeatureStage::discovery, 0, env.teb, entity, c.username_component);
        return {};
    }
    const auto now = std::chrono::steady_clock::now();
    auto stage = FeatureStage::component;
    bool graph_verified{}, reason_recorded{};
    const auto fail = [&](FeatureStage at, FeatureStatus status, const FeatureEvidence& evidence) {
        feature_trace.Record(Feature::name, at, status, evidence);
        reason_recorded = true;
        throw ReadFailure{ERROR_INVALID_DATA};
    };
    const auto stable_component = [&] {
        return c.component_count && c.username_index < c.component_count && Q(entity) == c.vtable &&
            Q(entity + c.component_offset) == c.list &&
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) == c.component_count &&
            Q(c.list + c.username_index * 8ull) == c.username_component &&
            Hash(c.username_component) == 0xd1d46a6fu;
    };
    try {
        if (!stable_component()) {
            c.username_component = c.name_profile = c.profile = 0;
            c.username.clear();
            c.affiliation_path.reset();
            c.next_components = {};
            feature_trace.Record(Feature::name, stage, FeatureStatus::state_changed,
                {.entity = entity,
                    .receiver = c.list,
                    .field = static_cast<std::uint64_t>(c.component_offset)});
            return {};
        }
        if (now - c.username_at < std::chrono::seconds(1)) {
            feature_trace.Record(Feature::name, FeatureStage::text,
                c.username.empty() ? FeatureStatus::unavailable : FeatureStatus::cached,
                {.entity = entity, .receiver = c.name_profile, .value = c.username.size()});
            return c.username;
        }
        c.username_at = now;
        const auto& path = native.usernames.front();
        const auto matches = [&](Address object, Address expected) {
            const auto info = TypeInfo(object);
            const auto range = Read<std::array<std::uint16_t, 2>>(info + 0x40);
            const auto base = Read<std::array<std::uint16_t, 2>>(expected);
            return range[0] >= base[0] && range[1] <= base[1];
        };
        const auto resolve_name = [&]() {
            stage = FeatureStage::owner;
            cpu.Reset(env.teb);
            cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
            if (!trace.Run(cpu, path.owner.code, "name_owner_emulation_failed", 0, module.address))
                fail(stage, FeatureStatus::emulation_failed,
                    {.entity = entity, .receiver = c.username_component});
            const auto owner = cpu.Get(path.owner.output);
            if (!Pointer(owner))
                fail(stage, FeatureStatus::uninitialized, {.entity = entity, .receiver = owner});
            const bool ai_owner = Hash(owner) == 0xc812b23du;
            if (!ai_owner && !matches(owner, path.owner_type)) {
                feature_trace.Receiver(process, module, sections, native.metadata, Feature::name, stage, 0,
                    env.teb, entity, owner);
                fail(stage, FeatureStatus::type_rejected,
                    {.entity = entity, .receiver = owner, .expected = path.owner_type});
            }
            stage = FeatureStage::profile;
            cpu.Reset(env.teb);
            cpu.Set(path.owner.output, owner);
            if (!trace.Run(cpu, path.profile.code, "name_profile_emulation_failed", 0, module.address))
                fail(stage, FeatureStatus::emulation_failed, {.entity = entity, .receiver = owner});
            const auto profile = cpu.Get(path.profile.output);
            if (!Pointer(profile))
                fail(stage, FeatureStatus::uninitialized,
                    {.entity = entity, .receiver = profile, .parent = owner});
            if (ai_owner ? Hash(profile) != 0x5d19580bu : !matches(profile, path.profile_type)) {
                feature_trace.Receiver(process, module, sections, native.metadata, Feature::name, stage, 0,
                    env.teb, entity, profile);
                fail(stage, FeatureStatus::type_rejected,
                    {.entity = entity, .receiver = profile, .parent = owner, .expected = path.profile_type});
            }
            return profile;
        };
        const auto profile = resolve_name();
        if (resolve_name() != profile || !stable_component())
            fail(FeatureStage::snapshot, FeatureStatus::state_changed,
                {.entity = entity, .receiver = profile});
        c.name_profile = profile;
        graph_verified = true;
        feature_trace.Record(Feature::name, FeatureStage::profile, FeatureStatus::ready,
            {.entity = entity, .receiver = profile});
        stage = FeatureStage::header;
        const auto field = path.string_field;
        const auto extent = Extent(profile, 0x10000);
        if (field + 16 > extent)
            fail(stage, FeatureStatus::extent_rejected,
                {.entity = entity, .receiver = profile, .field = field, .extent = extent});
        const auto string_header = Read<std::array<unsigned char, 16>>(profile + field);
        Address data = profile + field;
        std::uint32_t length{};
        if (string_header[0] || string_header[1] >= 4) {
            if (string_header[15] > 15)
                fail(stage, FeatureStatus::invalid_layout,
                    {.entity = entity, .receiver = profile, .field = field});
            length = 15 - string_header[15];
        } else {
            std::uint16_t size{};
            std::memcpy(&size, string_header.data() + 2, sizeof(size));
            length = size;
            if (string_header[1] == 1) {
                const auto storage = Q(profile + field + 8);
                if (size == 0xffff)
                    length = Read<std::uint32_t>(storage + 4);
                data = storage + 0xa;
            } else if (string_header[1] == 2) {
                if (length > 10)
                    fail(stage, FeatureStatus::invalid_layout,
                        {.entity = entity, .receiver = profile, .field = field, .value = length, .other = 2});
                data += 6;
            } else if (string_header[1] == 3)
                data = Q(profile + field + 8);
            else
                fail(stage, FeatureStatus::invalid_layout,
                    {.entity = entity,
                        .receiver = profile,
                        .field = field,
                        .value = length,
                        .other = string_header[1]});
        }
        if (!length || length > 256)
            fail(stage, !length ? FeatureStatus::uninitialized : FeatureStatus::invalid_value,
                {.entity = entity, .receiver = profile, .field = field, .value = length});
        feature_trace.Record(Feature::name, stage, FeatureStatus::ready,
            {.entity = entity,
                .receiver = profile,
                .field = field,
                .value = length,
                .other = static_cast<std::uint64_t>(
                    string_header[0] || string_header[1] >= 4 ? 0 : string_header[1])});
        stage = FeatureStage::text;
        const auto text = Array<char>(data, length);
        const bool controls =
            std::any_of(text.begin(), text.end(), [](unsigned char ch) { return ch < 32 || ch == 127; });
        const bool utf8 = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                              static_cast<int>(text.size()), nullptr, 0) != 0;
        if (controls || !utf8)
            fail(stage, FeatureStatus::invalid_value,
                {.entity = entity,
                    .receiver = profile,
                    .field = field,
                    .value = length,
                    .other = static_cast<std::uint64_t>(controls),
                    .observed = static_cast<std::uint64_t>(utf8)});
        graph_verified = false;
        if (resolve_name() != profile || !stable_component()) {
            fail(FeatureStage::snapshot, FeatureStatus::state_changed,
                {.entity = entity, .receiver = profile});
        }
        graph_verified = true;
        stage = FeatureStage::header;
        if (Read<std::array<unsigned char, 16>>(profile + field) != string_header)
            fail(FeatureStage::header, FeatureStatus::state_changed,
                {.entity = entity, .receiver = profile, .field = field, .value = length});
        stage = FeatureStage::text;
        if (Array<char>(data, length) != text)
            fail(FeatureStage::text, FeatureStatus::state_changed,
                {.entity = entity, .receiver = profile, .field = field, .value = length});
        c.username.assign(text.begin(), text.end());
        c.name_profile = profile;
        feature_trace.Record(Feature::name, FeatureStage::text, FeatureStatus::ready,
            {.entity = entity, .receiver = profile, .field = field, .value = length});
    } catch (const ReadFailure& failure) {
        c.username.clear();
        if (!graph_verified)
            c.name_profile = 0;
        if (!reason_recorded)
            feature_trace.Record(Feature::name, stage, FeatureStatus::read_failed,
                {.entity = entity, .receiver = c.name_profile, .win32 = failure.error});
    }
    return c.username;
}
}
