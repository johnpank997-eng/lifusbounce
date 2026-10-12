#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::SelectedOperatorFor(Address entity, const CachedEntity& c) -> std::uint32_t {
    if (!c.name_profile || c.username.empty() || !selected || !native.selected_operator || !metadata ||
        native.usernames.size() != 1)
        return 0;
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
            if (metadata_hash(path.definition_type - 0x40) != 0xafcc12eau)
                return 0;
            std::optional<std::size_t> match;
            for (std::size_t i = 0; i < native.operator_names.size(); ++i)
                if (metadata_hash(native.operator_names[i].target_type - 0x40) == 0x9791ffa6u) {
                    if (match)
                        return 0;
                    match = i;
                }
            if (!match)
                return 0;
            operator_name_path = match;
        }
        const auto& name_path = native.operator_names[*operator_name_path];
        const auto profile = c.name_profile;
        const auto profile_vtable = Q(profile);
        if (path.instance_field + 8 > Extent(profile, 0x10000))
            return 0;
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
            if (!cpu.Run(names.owner.code).Complete())
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
            if (!cpu.Run(names.profile.code).Complete())
                return 0;
            return cpu.Get(names.profile.output);
        };
        if (resolve_profile() != profile)
            return 0;
        const auto initialized = [&](Address reference) -> Address {
            if (!Pointer(reference) || !(Read<std::uint32_t>(reference + 8) & 0x80000000u))
                return 0;
            return Q(reference);
        };
        const auto instance_ref = Evaluate(path.instance, selected->teb, profile);
        const auto instance = initialized(instance_ref);
        if (!instance || Hash(instance) != 0x88088032u ||
            path.definition_field + 8 > Extent(instance, 0x10000))
            return 0;
        const auto instance_vtable = Q(instance);
        const auto definition_ref = Evaluate(path.definition, selected->teb, instance);
        const auto definition = initialized(definition_ref);
        if (!definition || Hash(definition) != 0xafcc12eau ||
            name_path.field + 8 > Extent(definition, 0x10000))
            return 0;
        const auto definition_vtable = Q(definition);
        const auto name_ref = Evaluate(name_path.reference, selected->teb, definition);
        const auto name = initialized(name_ref);
        if (!name || Hash(name) != 0x9791ffa6u || Extent(name, 0x10000) < 0x18)
            return 0;
        const auto name_vtable = Q(name), packed = Q(name + 0x10);
        if (packed & 0x3ffffu)
            return 0;
        const auto identity = operators::NameDefinitionIdentity(packed >> 18);
        if (!identity || resolve_profile() != profile || Q(profile) != profile_vtable ||
            Evaluate(path.instance, selected->teb, profile) != instance_ref ||
            initialized(instance_ref) != instance || Q(instance) != instance_vtable ||
            Evaluate(path.definition, selected->teb, instance) != definition_ref ||
            initialized(definition_ref) != definition || Q(definition) != definition_vtable ||
            Evaluate(name_path.reference, selected->teb, definition) != name_ref ||
            initialized(name_ref) != name || Q(name) != name_vtable || Q(name + 0x10) != packed)
            return 0;
        return identity;
    } catch (ReadFailure) {
        return 0;
    }
}

auto Reader::Implementation::AnimationOperatorFor(Address entity, const CachedEntity& c) -> std::uint32_t {
    try {
        const auto stable_body = [&] {
            return c.animation_component && c.animation_index < c.component_count && Q(entity) == c.vtable &&
                Q(entity + c.component_offset) == c.list &&
                (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) == c.component_count &&
                Q(c.list + c.animation_index * 8ull) == c.animation_component;
        };
        if (!stable_body() || Hash(c.animation_component) != 0x4e4b0976u)
            return 0;
        const auto animation = c.animation_component, table = Q(animation);
        auto& binding = animation_operators[table];
        const auto now = std::chrono::steady_clock::now();
        if (!binding.path && now >= binding.retry) {
            binding.retry = now + std::chrono::seconds(2);
            std::set<Address> methods, producers;
            std::optional<operators::ModuleLayout> accepted;
            for (const auto method : Array<Address>(table, 64)) {
                if (!methods.insert(method).second)
                    continue;
                try {
                    const auto& code = EquipmentCode(method);
                    if (!code)
                        continue;
                    auto path = operators::AnimationModules(*code);
                    const auto producer = operators::ReceiverCall(*code);
                    if (!path && producer && producers.insert(*producer).second) {
                        const auto& body = EquipmentCode(*producer);
                        if (body)
                            path = operators::AnimationModules(*body);
                    }
                    if (!path)
                        continue;
                    if (accepted && *accepted != *path)
                        return 0;
                    accepted = path;
                } catch (ReadFailure) {
                }
            }
            binding.path = accepted;
        }
        if (!binding.path)
            return 0;
        const auto& path = *binding.path;
        const auto size = Extent(animation, 0x10000);
        if (path.checksum + 4 > size || path.primary + 8 > size || path.modules + 8 > size ||
            path.count + 4 > size)
            return 0;
        const auto raw = Read<std::uint32_t>(animation + path.checksum);
        const auto primary = Q(animation + path.primary), list = Q(animation + path.modules);
        const auto count = Read<std::uint32_t>(animation + path.count) & 0x3fffffffu;
        if (count > 63)
            return 0;
        auto wrappers = count ? Array<Address>(list, count) : std::vector<Address>{};
        wrappers.insert(wrappers.begin(), primary);

        struct Resource {
            Address wrapper, object, table;
            std::uint32_t signature;
        };

        std::vector<Resource> resources;
        std::vector<std::uint32_t> signatures;
        std::uint32_t crc = 0xffffffffu;
        for (const auto wrapper : wrappers) {
            if (!(Read<std::uint32_t>(wrapper + path.flags) & 0x80000000u))
                return 0;
            const auto object = Q(wrapper + path.data);
            if (Hash(object) != 0xc34a348fu || path.signature + 4 > Extent(object, 0x10000))
                return 0;
            const auto signature = Read<std::uint32_t>(object + path.signature);
            crc = operators::AppendCrc(crc, signature);
            signatures.push_back(signature);
            resources.push_back({wrapper, object, Q(object), signature});
        }
        if (~crc != raw)
            return 0;
        const auto identity = operators::BaseIdentity(signatures);
        if (!identity)
            return 0;
        for (const auto& resource : resources)
            if (!(Read<std::uint32_t>(resource.wrapper + path.flags) & 0x80000000u) ||
                Q(resource.wrapper + path.data) != resource.object || Q(resource.object) != resource.table ||
                Read<std::uint32_t>(resource.object + path.signature) != resource.signature)
                return 0;
        if (!stable_body() || Q(animation) != table || Q(animation + path.primary) != primary ||
            Q(animation + path.modules) != list ||
            (Read<std::uint32_t>(animation + path.count) & 0x3fffffffu) != count ||
            (count &&
                Array<Address>(list, count) != std::vector<Address>(wrappers.begin() + 1, wrappers.end())) ||
            Read<std::uint32_t>(animation + path.checksum) != raw)
            return 0;
        return *identity;
    } catch (ReadFailure) {
        return 0;
    }
}

auto Reader::Implementation::OperatorFor(Address entity, const CachedEntity& c) -> std::uint32_t {
    if (const auto identity = SelectedOperatorFor(entity, c))
        return identity;
    return AnimationOperatorFor(entity, c);
}

auto Reader::Implementation::UnownedModelFor(Address entity, const CachedEntity& c) -> bool {
    if (!selected || !c.username_component || c.name_profile || c.profile || !c.username.empty() ||
        native.usernames.size() != 1 || c.username_index >= c.component_count)
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
        const auto& names = native.usernames.front();
        const auto resolve_owner = [&] {
            cpu.Reset(selected->teb);
            cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
            if (!cpu.Run(names.owner.code).Complete())
                throw ReadFailure{ERROR_INVALID_DATA};
            return cpu.Get(names.owner.output);
        };
        const auto owner = resolve_owner(), table = Q(owner);
        if (Hash(owner) != 0xc812b23du)
            return false;
        const auto resolve_profile = [&] {
            cpu.Reset(selected->teb);
            cpu.Set(names.owner.output, owner);
            if (!cpu.Run(names.profile.code).Complete())
                throw ReadFailure{ERROR_INVALID_DATA};
            return cpu.Get(names.profile.output);
        };
        return resolve_profile() == 0 && resolve_owner() == owner && Q(owner) == table &&
            resolve_profile() == 0 && stable();
    } catch (ReadFailure) {
        return false;
    }
}
}
