#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::SelectedOperatorFor(Address entity, const CachedEntity& c) -> std::uint32_t {
    auto stage = FeatureStage::discovery;
    const auto record = [&](FeatureStatus status, FeatureEvidence evidence = {}) {
        evidence.entity = entity;
        feature_trace.Record(Feature::operator_id, stage, status, evidence);
        if (status != FeatureStatus::ready && evidence.receiver)
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::operator_id, stage,
                evidence.path, selected ? selected->teb : 0, entity, evidence.receiver);
        return 0u;
    };
    if (!c.name_profile || !selected || !native.selected_operator || !metadata ||
        native.usernames.size() != 1)
        return record(FeatureStatus::missing_path,
            {.receiver = c.name_profile,
                .value = native.usernames.size(),
                .other = native.selected_operator.has_value()});
    try {
        const auto metadata_hash = [&](Address info) {
            if (!Section(info))
                throw ReadFailure{ERROR_INVALID_DATA};
            constexpr Address object = 0x60000000000ull, table = object + 0x1000;
            std::array<std::byte, 0x1000> bytes{};
            if (metadata->table_field + 8 > bytes.size())
                throw ReadFailure{ERROR_INVALID_DATA};
            std::memcpy(bytes.data() + metadata->table_field, &info, 8);
            cpu.Reset();
            cpu.Input(object, std::as_bytes(std::span(&table, 1)));
            cpu.Input(table, bytes);
            cpu.Set(ZYDIS_REGISTER_RCX, object);
            if (!cpu.Run(metadata->decode.code).Complete())
                throw ReadFailure{ERROR_NOT_SUPPORTED};
            return static_cast<std::uint32_t>(cpu.Get(metadata->decode.output));
        };
        const auto& path = *native.selected_operator;
        if (!operator_name_path) {
            stage = FeatureStage::definition;
            const auto target = metadata_hash(path.definition_type - 0x40);
            if (target != 0xafcc12eau)
                return record(FeatureStatus::type_rejected,
                    {.address = path.definition_type, .expected = 0xafcc12eau, .observed = target});
            stage = FeatureStage::reference;
            std::optional<std::size_t> match;
            for (std::size_t i = 0; i < native.operator_names.size(); ++i)
                if (metadata_hash(native.operator_names[i].target_type - 0x40) == 0x9791ffa6u) {
                    if (match)
                        return record(FeatureStatus::ambiguous_path, {.value = *match, .other = i});
                    match = i;
                }
            if (!match)
                return record(FeatureStatus::missing_path, {.value = native.operator_names.size()});
            operator_name_path = match;
        }
        if (*operator_name_path >= native.operator_names.size())
            return record(FeatureStatus::invalid_layout, {.value = *operator_name_path});
        const auto& name_path = native.operator_names[*operator_name_path];
        const auto profile = c.name_profile;
        stage = FeatureStage::profile;
        const auto profile_vtable = Q(profile), profile_size = Extent(profile, 0x10000);
        if (path.instance_field + 8 > profile_size)
            return record(FeatureStatus::extent_rejected,
                {.receiver = profile, .field = path.instance_field, .extent = profile_size});
        const auto resolve_profile = [&]() -> Address {
            if (c.username_index >= c.component_count || Q(entity) != c.vtable ||
                Q(entity + c.component_offset) != c.list ||
                (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
                Q(c.list + c.username_index * 8ull) != c.username_component ||
                Hash(c.username_component) != 0xd1d46a6fu)
                return 0;
            const auto& names = native.usernames.front();
            cpu.Reset(selected->teb);
            cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
            if (!trace.Execute(cpu, names.owner.code, "operator_owner", 0, module.address).Complete())
                return 0;
            const auto owner = cpu.Get(names.owner.output);
            const auto owner_type = Hash(owner);
            if (owner_type != 0xc812b23du) {
                const auto range = Read<std::array<std::uint16_t, 2>>(TypeInfo(owner) + 0x40);
                const auto expected = Read<std::array<std::uint16_t, 2>>(names.owner_type);
                if (range[0] < expected[0] || range[1] > expected[1])
                    return 0;
            }
            cpu.Reset(selected->teb);
            cpu.Set(names.owner.output, owner);
            if (!trace.Execute(cpu, names.profile.code, "operator_profile", 0, module.address).Complete())
                return 0;
            const auto resolved = cpu.Get(names.profile.output);
            if (!Pointer(resolved))
                return 0;
            if (owner_type == 0xc812b23du) {
                if (Hash(resolved) != 0x5d19580bu)
                    return 0;
            } else {
                const auto range = Read<std::array<std::uint16_t, 2>>(TypeInfo(resolved) + 0x40);
                const auto expected = Read<std::array<std::uint16_t, 2>>(names.profile_type);
                if (range[0] < expected[0] || range[1] > expected[1])
                    return 0;
            }
            return resolved;
        };
        if (resolve_profile() != profile)
            return record(FeatureStatus::state_changed, {.receiver = profile});
        const auto initialized = [&](Address reference) -> Address {
            if (!Pointer(reference) || !(Read<std::uint32_t>(reference + 8) & 0x80000000u))
                return 0;
            return Q(reference);
        };
        stage = FeatureStage::instance;
        const auto instance_ref = Evaluate(path.instance, selected->teb, profile, "operator_instance", 0);
        const auto instance = initialized(instance_ref);
        if (!instance)
            return record(FeatureStatus::uninitialized, {.receiver = profile, .address = instance_ref});
        const auto instance_type = Hash(instance);
        const auto instance_size = Extent(instance, 0x10000);
        if (instance_type != 0x88088032u)
            return record(FeatureStatus::type_rejected,
                {.receiver = instance, .expected = 0x88088032u, .observed = instance_type});
        if (path.definition_field + 8 > instance_size)
            return record(FeatureStatus::extent_rejected,
                {.receiver = instance, .field = path.definition_field, .extent = instance_size});
        const auto instance_vtable = Q(instance);
        stage = FeatureStage::definition;
        const auto definition_ref =
            Evaluate(path.definition, selected->teb, instance, "operator_definition", 0);
        const auto definition = initialized(definition_ref);
        if (!definition)
            return record(FeatureStatus::uninitialized, {.receiver = instance, .address = definition_ref});
        const auto definition_type = Hash(definition);
        const auto definition_size = Extent(definition, 0x10000);
        if (definition_type != 0xafcc12eau)
            return record(FeatureStatus::type_rejected,
                {.receiver = definition, .expected = 0xafcc12eau, .observed = definition_type});
        if (name_path.field + 8 > definition_size)
            return record(FeatureStatus::extent_rejected,
                {.receiver = definition, .field = name_path.field, .extent = definition_size});
        const auto definition_vtable = Q(definition);
        stage = FeatureStage::reference;
        const auto name_ref = Evaluate(
            name_path.reference, selected->teb, definition, "operator_name_reference", *operator_name_path);
        const auto name = initialized(name_ref);
        if (!name)
            return record(FeatureStatus::uninitialized, {.receiver = definition, .address = name_ref});
        const auto name_type = Hash(name);
        const auto name_size = Extent(name, 0x10000);
        if (name_type != 0x9791ffa6u)
            return record(FeatureStatus::type_rejected,
                {.receiver = name, .expected = 0x9791ffa6u, .observed = name_type});
        if (name_size < 0x18)
            return record(FeatureStatus::extent_rejected, {.receiver = name, .extent = name_size});
        const auto name_vtable = Q(name), packed = Q(name + 0x10);
        stage = FeatureStage::header;
        if (packed & 0x3ffffu)
            return record(
                FeatureStatus::invalid_layout, {.receiver = name, .address = name + 0x10, .value = packed});
        stage = FeatureStage::mapping;
        const auto identity = operators::NameDefinitionIdentity(packed >> 18);
        if (!identity)
            return record(FeatureStatus::mapping_missing, {.receiver = name, .value = packed >> 18});
        stage = FeatureStage::snapshot;
        if (resolve_profile() != profile || Q(profile) != profile_vtable ||
            Evaluate(path.instance, selected->teb, profile) != instance_ref ||
            initialized(instance_ref) != instance || Q(instance) != instance_vtable ||
            Evaluate(path.definition, selected->teb, instance) != definition_ref ||
            initialized(definition_ref) != definition || Q(definition) != definition_vtable ||
            Evaluate(name_path.reference, selected->teb, definition) != name_ref ||
            initialized(name_ref) != name || Q(name) != name_vtable || Q(name + 0x10) != packed)
            return record(FeatureStatus::state_changed, {.receiver = name, .value = identity});
        record(FeatureStatus::ready, {.receiver = name, .value = identity, .other = packed >> 18});
        return identity;
    } catch (ReadFailure failure) {
        return record(failure.error == ERROR_NOT_SUPPORTED ? FeatureStatus::emulation_failed
                                                           : FeatureStatus::read_failed,
            {.win32 = failure.error});
    }
}

auto Reader::Implementation::AnimationOperatorFor(Address entity, const CachedEntity& c) -> std::uint32_t {
    auto stage = FeatureStage::component;
    const auto record = [&](FeatureStatus status, FeatureEvidence evidence = {}) {
        evidence.entity = entity;
        feature_trace.Record(Feature::operator_id, stage, status, evidence);
        if (status != FeatureStatus::ready && evidence.receiver)
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::operator_id, stage,
                evidence.path, selected ? selected->teb : 0, entity, evidence.receiver);
        return 0u;
    };
    try {
        const auto stable_body = [&] {
            return c.animation_component && c.animation_index < c.component_count && Q(entity) == c.vtable &&
                Q(entity + c.component_offset) == c.list &&
                (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) == c.component_count &&
                Q(c.list + c.animation_index * 8ull) == c.animation_component;
        };
        if (!stable_body())
            return record(FeatureStatus::state_changed, {.receiver = c.animation_component});
        const auto animation_type = Hash(c.animation_component);
        if (animation_type != 0x4e4b0976u)
            return record(FeatureStatus::type_rejected,
                {.receiver = c.animation_component, .expected = 0x4e4b0976u, .observed = animation_type});
        const auto animation = c.animation_component, table = Q(animation);
        stage = FeatureStage::animation_layout;
        auto& binding = animation_operators[table];
        const auto now = std::chrono::steady_clock::now();
        if (!binding.path && now >= binding.retry) {
            binding.retry = now + std::chrono::seconds(2);
            std::set<Address> methods, producers;
            std::optional<operators::ModuleLayout> accepted;
            const auto entries = Array<Address>(table, 64);
            for (std::size_t slot = 0; slot < entries.size(); ++slot) {
                const auto method = entries[slot];
                if (!methods.insert(method).second)
                    continue;
                try {
                    const auto& code = EquipmentCode(method);
                    if (!code)
                        continue;
                    const auto discover = [&](const Emulator::Program& candidate) {
                        auto end = candidate.end;
                        const auto rva = candidate.begin - module.address;
                        auto function = std::upper_bound(native.functions.begin(), native.functions.end(),
                            rva, [](Address at, const auto& f) { return at < f.begin; });
                        if (function != native.functions.begin()) {
                            --function;
                            if (function->begin <= rva && rva < function->end &&
                                function->end - rva <= 0x10000)
                                end = module.address + function->end;
                        }
                        const auto table_word = [&](Address at) -> std::optional<std::int32_t> {
                            if (at < candidate.begin || at > end || end - at < 4 ||
                                at < module.address + header.OptionalHeader.BaseOfCode ||
                                at - module.address - header.OptionalHeader.BaseOfCode + 4 >
                                    header.OptionalHeader.SizeOfCode)
                                return std::nullopt;
                            return Read<std::int32_t>(at);
                        };
                        operators::ModuleDiscovery result;
                        auto path = operators::AnimationModules(candidate, table_word, &result, end);
                        if (!path)
                            record(FeatureStatus::missing_path,
                                {.path = slot + 2,
                                    .address = candidate.begin,
                                    .value = static_cast<unsigned>(result.rejection),
                                    .other = result.stores,
                                    .expected = result.arrays,
                                    .observed = result.primary});
                        return path;
                    };
                    auto path = discover(*code);
                    const auto producer = operators::ReceiverCall(*code);
                    if (!path && producer && producers.insert(*producer).second) {
                        const auto& body = EquipmentCode(*producer);
                        if (body)
                            path = discover(*body);
                    }
                    if (!path)
                        continue;
                    if (accepted && *accepted != *path)
                        return record(FeatureStatus::ambiguous_path,
                            {.path = 1,
                                .receiver = animation,
                                .address = table,
                                .value = accepted->producer,
                                .other = path->producer});
                    accepted = path;
                } catch (ReadFailure failure) {
                    record(FeatureStatus::read_failed,
                        {.path = slot + 2, .address = method, .win32 = failure.error});
                }
            }
            binding.path = accepted;
        }
        if (!binding.path)
            return record(FeatureStatus::missing_path, {.path = 1, .receiver = animation, .address = table});
        const auto& path = *binding.path;
        if ((path.count_width != 32 && path.count_width != 64) ||
            (path.count_shift_width != 32 && path.count_shift_width != 64) || path.count_mask < 63 ||
            path.count_mask > 0x3fffffffu || (path.count_mask & (path.count_mask + 1)))
            return record(FeatureStatus::invalid_layout,
                {.path = 1,
                    .receiver = animation,
                    .field = path.count,
                    .expected = path.count_width,
                    .observed = path.count_mask});
        const auto size = Extent(animation, 0x10000);
        if (path.checksum + 4 > size || path.primary + 8 > size || path.modules + 8 > size ||
            path.count + path.count_width / 8 > size || (path.checksum_high && path.checksum_high + 4 > size))
            return record(FeatureStatus::extent_rejected,
                {.path = 1,
                    .receiver = animation,
                    .field = path.checksum,
                    .extent = size,
                    .value = path.primary,
                    .other = path.modules});
        record(FeatureStatus::ready,
            {.path = 1,
                .receiver = animation,
                .address = path.producer,
                .field = path.checksum,
                .extent = size,
                .value = path.primary,
                .other = path.modules,
                .expected = path.count,
                .observed = path.signature});
        stage = FeatureStage::animation_modules;
        record(FeatureStatus::ready,
            {.path = 1,
                .receiver = animation,
                .address = path.count_consumer,
                .field = path.count_mask_store,
                .value = path.count_direct_consumer,
                .other = static_cast<std::uint64_t>(path.count_mask_slot),
                .expected = path.count_shift_width,
                .observed = path.checksum_high});
        if (path.count_mask_store)
            record(FeatureStatus::ready,
                {.path = 1,
                    .receiver = animation,
                    .address = path.count_mask_store,
                    .value = path.count_byte_mask,
                    .other = static_cast<std::uint64_t>(path.count_mask_slot),
                    .expected = path.count_direct_width,
                    .observed = path.count_direct_shift_width});
        const auto count_value = [&]() -> std::uint64_t {
            return (path.count_width == 64 ? Q(animation + path.count)
                                           : Read<std::uint32_t>(animation + path.count)) &
                path.count_mask;
        };
        const auto raw = Read<std::uint32_t>(animation + path.checksum);
        const auto raw_high = path.checksum_high ? Read<std::uint32_t>(animation + path.checksum_high) : 0;
        const auto primary = Q(animation + path.primary), list = Q(animation + path.modules);
        const auto count = count_value();
        record(FeatureStatus::ready,
            {.path = 1,
                .receiver = animation,
                .field = path.count,
                .value = count,
                .expected = path.count_width,
                .observed = path.count_mask});
        if (count > 63)
            return record(FeatureStatus::invalid_value,
                {.path = 1, .receiver = animation, .address = list, .value = count, .expected = 63});
        auto wrappers = count ? Array<Address>(list, count) : std::vector<Address>{};
        wrappers.insert(wrappers.begin(), primary);

        struct Resource {
            Address wrapper, object, table;
            std::uint32_t signature;
            std::uint32_t signature_high;
        };

        std::vector<Resource> resources;
        std::vector<std::uint32_t> signatures;
        std::uint32_t crc = 0xffffffffu;
        std::uint32_t crc_high = 0xffffffffu;
        for (const auto wrapper : wrappers) {
            const auto flags = Read<std::uint32_t>(wrapper + path.flags);
            if (!(flags & 0x80000000u))
                return record(FeatureStatus::uninitialized,
                    {.path = 1, .receiver = animation, .address = wrapper, .value = flags});
            const auto object = Q(wrapper + path.data);
            const auto type = Hash(object);
            const auto extent = Extent(object, 0x10000);
            if (type != 0xc34a348fu)
                return record(FeatureStatus::type_rejected,
                    {.path = 1,
                        .receiver = object,
                        .address = wrapper,
                        .expected = 0xc34a348fu,
                        .observed = type});
            if (path.signature + (path.checksum_high ? 8 : 4) > extent)
                return record(FeatureStatus::extent_rejected,
                    {.path = 1, .receiver = object, .field = path.signature, .extent = extent});
            const auto signature = Read<std::uint32_t>(object + path.signature);
            const auto signature_high =
                path.checksum_high ? Read<std::uint32_t>(object + path.signature + 4) : 0;
            crc = operators::AppendCrc(crc, signature);
            if (path.checksum_high)
                crc_high = operators::AppendCrc(crc_high, signature_high);
            signatures.push_back(signature);
            resources.push_back({wrapper, object, Q(object), signature, signature_high});
            record(FeatureStatus::ready,
                {.path = 1,
                    .receiver = object,
                    .address = wrapper,
                    .field = path.signature,
                    .extent = extent,
                    .value = signature,
                    .other = resources.size()});
        }
        stage = FeatureStage::checksum;
        if (~crc != raw)
            return record(FeatureStatus::invalid_value,
                {.path = 1,
                    .receiver = animation,
                    .value = raw,
                    .other = count,
                    .expected = raw,
                    .observed = static_cast<std::uint32_t>(~crc)});
        if (path.checksum_high && ~crc_high != raw_high)
            return record(FeatureStatus::invalid_value,
                {.path = 1,
                    .receiver = animation,
                    .field = path.checksum_high,
                    .value = raw_high,
                    .other = count,
                    .expected = raw_high,
                    .observed = static_cast<std::uint32_t>(~crc_high)});
        if (path.checksum_high)
            record(FeatureStatus::ready,
                {.path = 1,
                    .receiver = animation,
                    .field = path.checksum_high,
                    .expected = raw_high,
                    .observed = static_cast<std::uint32_t>(~crc_high)});
        stage = FeatureStage::mapping;
        const auto identity = operators::BaseIdentity(signatures);
        if (!identity)
            return record(FeatureStatus::mapping_missing,
                {.path = 1, .receiver = animation, .value = raw, .other = count});
        stage = FeatureStage::snapshot;
        for (const auto& resource : resources)
            if (!(Read<std::uint32_t>(resource.wrapper + path.flags) & 0x80000000u) ||
                Q(resource.wrapper + path.data) != resource.object || Q(resource.object) != resource.table ||
                Read<std::uint32_t>(resource.object + path.signature) != resource.signature ||
                (path.checksum_high &&
                    Read<std::uint32_t>(resource.object + path.signature + 4) != resource.signature_high))
                return record(FeatureStatus::state_changed,
                    {.path = 1, .receiver = resource.object, .address = resource.wrapper});
        if (!stable_body() || Q(animation) != table || Q(animation + path.primary) != primary ||
            Q(animation + path.modules) != list || count_value() != count ||
            (count &&
                Array<Address>(list, count) != std::vector<Address>(wrappers.begin() + 1, wrappers.end())) ||
            Read<std::uint32_t>(animation + path.checksum) != raw ||
            (path.checksum_high && Read<std::uint32_t>(animation + path.checksum_high) != raw_high))
            return record(
                FeatureStatus::state_changed, {.path = 1, .receiver = animation, .value = *identity});
        record(FeatureStatus::ready, {.path = 1, .receiver = animation, .value = *identity, .other = raw});
        return *identity;
    } catch (ReadFailure failure) {
        return record(FeatureStatus::read_failed, {.path = 1, .win32 = failure.error});
    }
}

auto Reader::Implementation::OperatorFor(Address entity, const CachedEntity& c) -> std::uint32_t {
    if (const auto identity = SelectedOperatorFor(entity, c))
        return identity;
    return AnimationOperatorFor(entity, c);
}

auto Reader::Implementation::UnownedModelFor(Address entity, const CachedEntity& c) -> bool {
    if (!selected || !c.username_component || c.name_profile || c.profile || !c.username.empty() ||
        (native.ownership.empty() && native.usernames.size() != 1) || c.username_index >= c.component_count)
        return false;
    try {
        const auto source_table = Q(c.username_component);
        const auto stable = [&] {
            return Q(entity) == c.vtable && Q(entity + c.component_offset) == c.list &&
                (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) == c.component_count &&
                Q(c.list + c.username_index * 8ull) == c.username_component &&
                Q(c.username_component) == source_table;
        };
        if (!stable() || Hash(c.username_component) != 0xd1d46a6fu)
            return false;
        const auto inspect = [&](const auto& path) -> std::optional<std::pair<Address, bool>> {
            const auto resolve_owner = [&] {
                cpu.Reset(selected->teb);
                cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
                if (!cpu.Run(path.owner.code).Complete())
                    throw ReadFailure{ERROR_INVALID_DATA};
                return cpu.Get(path.owner.output);
            };
            const auto owner = resolve_owner(), table = Q(owner);
            if (Hash(owner) != 0xc812b23du)
                return std::nullopt;
            const auto resolve_profile = [&] {
                cpu.Reset(selected->teb);
                cpu.Set(path.owner.output, owner);
                if (!cpu.Run(path.profile.code).Complete())
                    throw ReadFailure{ERROR_INVALID_DATA};
                return cpu.Get(path.profile.output);
            };
            const auto profile = resolve_profile();
            if ((profile && Hash(profile) != 0x5d19580bu) || resolve_owner() != owner || Q(owner) != table ||
                resolve_profile() != profile || !stable())
                return std::nullopt;
            return std::pair{owner, profile == 0};
        };
        if (native.ownership.empty()) {
            const auto result = inspect(native.usernames.front());
            return result && result->second;
        }
        std::optional<Address> accepted;
        for (const auto& path : native.ownership)
            try {
                if (const auto result = inspect(path)) {
                    if (!result->second || (accepted && *accepted != result->first))
                        return false;
                    accepted = result->first;
                }
            } catch (ReadFailure) {
            }
        return accepted.has_value();
    } catch (ReadFailure) {
        return false;
    }
}
}
