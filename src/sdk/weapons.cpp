#include "sdk/reader_internal.hpp"
#include "core/diagnostics.hpp"

namespace base::sdk {
auto Reader::Implementation::EquipmentCode(Address method) -> const std::optional<Emulator::Program>& {
    if (const auto found = equipment_methods.find(method); found != equipment_methods.end())
        return found->second;
    const auto code_begin = module.address + header.OptionalHeader.BaseOfCode;
    const auto code_end = code_begin + header.OptionalHeader.SizeOfCode;
    if (method < code_begin || method >= code_end)
        throw ReadFailure{ERROR_INVALID_DATA};
    std::size_t size = static_cast<std::size_t>(std::min<Address>(0x400, code_end - method));
    bool listed{};
    const auto rva = method - module.address;
    auto record = std::upper_bound(native.functions.begin(), native.functions.end(), rva,
        [](Address at, const auto& f) { return at < f.begin; });
    if (record != native.functions.begin()) {
        --record;
        if (record->begin <= rva && rva < record->end) {
            size = static_cast<std::size_t>(record->end - rva);
            listed = true;
        }
    }
    if (!size || size > 0x10000 || size > code_end - method)
        throw ReadFailure{ERROR_INVALID_DATA};
    auto code = Emulator::Decode(Array<std::byte>(method, size), method, true);
    if (code && !listed) {
        const auto stop =
            std::find_if(code->instructions.begin(), code->instructions.end(), [](const auto& d) {
                return d.instruction.mnemonic == ZYDIS_MNEMONIC_RET ||
                    d.instruction.mnemonic == ZYDIS_MNEMONIC_INT3 ||
                    d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
            });
        if (stop != code->instructions.end()) {
            code->end = stop->address + stop->instruction.length;
            code->instructions.erase(stop + 1, code->instructions.end());
        }
    }
    return equipment_methods.emplace(method, std::move(code)).first->second;
}

auto Reader::Implementation::ResourceName(Address resource, const Environment& env) -> std::string {
    FeatureEvidence evidence{.receiver = resource};
    auto stage = FeatureStage::codec;
    const auto record = [&](FeatureStatus status) {
        feature_trace.Record(Feature::weapon, stage, status, evidence);
    };
    const auto table = Q(resource);
    const auto size = Extent(resource, 0x10000);
    auto& search = weapon_names[table];
    const auto now = std::chrono::steady_clock::now();
    if (!search.path && now >= search.retry) {
        search.retry = now + std::chrono::seconds(2);
        std::optional<WeaponNamePath> accepted;
        Address accepted_field{};
        const auto prefix =
            Array<Address>(resource, static_cast<std::size_t>(std::min<Address>(size, 0x400) / 8));
        for (std::size_t index = 0; index < prefix.size(); ++index) {
            if (!Section(prefix[index]))
                continue;
            const auto object = resource + index * 8;
            try {
                TypeInfo(object);
                const auto object_size = Extent(object, 0x10000);
                if (object_size > size - index * 8)
                    continue;
                evidence.path = index;
                evidence.address = object;
                evidence.field = index * 8;
                evidence.extent = object_size;
                record(FeatureStatus::ready);
                std::set<Address> visited;
                const auto methods = Array<Address>(prefix[index], 24);
                for (const auto method : methods)
                    try {
                        if (!visited.insert(method).second)
                            continue;
                        const auto& body = EquipmentCode(method);
                        if (!body)
                            continue;
                        for (auto& member : locators::SerializedMembers(*body))
                            try {
                                const auto& dispatcher = EquipmentCode(member.dispatcher);
                                if (!dispatcher)
                                    continue;
                                const auto codec_field = locators::SerializationCodecField(*dispatcher);
                                if (!codec_field)
                                    continue;
                                cpu.Reset(env.teb);
                                if (!trace.Run(cpu, member.descriptor.code, "weapon_name_descriptor", index,
                                        module.address)) {
                                    record(FeatureStatus::emulation_failed);
                                    continue;
                                }
                                const auto descriptor = cpu.Get(member.descriptor.output);
                                if (!Section(descriptor) || !Section(descriptor + *codec_field))
                                    continue;
                                const auto callback = Q(descriptor + *codec_field);
                                const auto& codec = EquipmentCode(callback);
                                if (!codec)
                                    continue;
                                const auto characters = locators::InlineNameCodec(*codec);
                                if (!characters)
                                    continue;
                                const auto& string_codec = EquipmentCode(*characters);
                                if (!string_codec || !locators::InlineStringCodec(*string_codec))
                                    continue;
                                cpu.Reset(env.teb);
                                cpu.Set(ZYDIS_REGISTER_RCX, object);
                                if (!trace.Run(
                                        cpu, member.data.code, "weapon_name_data", index, module.address)) {
                                    record(FeatureStatus::emulation_failed);
                                    continue;
                                }
                                const auto data = cpu.Get(member.data.output);
                                if (data < object || data - object > object_size ||
                                    object_size - (data - object) < 32)
                                    continue;
                                const auto field = data - resource;
                                if (Q(object) != prefix[index] || Q(descriptor + *codec_field) != callback)
                                    throw ReadFailure{ERROR_NOT_READY};
                                if (accepted && accepted_field != field)
                                    throw ReadFailure{ERROR_DUP_NAME};
                                if (!accepted) {
                                    accepted = WeaponNamePath{index * 8, prefix[index],
                                        std::move(member.data), method, member.dispatcher, descriptor,
                                        *codec_field, callback, *characters};
                                    accepted_field = field;
                                }
                            } catch (ReadFailure failure) {
                                if (failure.error == ERROR_DUP_NAME)
                                    throw;
                            }
                    } catch (ReadFailure failure) {
                        if (failure.error == ERROR_DUP_NAME)
                            throw;
                    }
            } catch (ReadFailure failure) {
                if (failure.error == ERROR_DUP_NAME)
                    throw;
            }
        }
        search.path = std::move(accepted);
        if (search.path) {
            const auto& path = *search.path;
            diagnostics::Write("weapon_name_binding",
                {{"resource", diagnostics::Hex(resource)}, {"object_offset", path.object_offset},
                    {"object_vtable", diagnostics::Hex(path.object_vtable)},
                    {"serializer_rva", diagnostics::Hex(path.serializer - module.address)},
                    {"dispatcher_rva", diagnostics::Hex(path.dispatcher - module.address)},
                    {"descriptor_rva", diagnostics::Hex(path.descriptor - module.address)},
                    {"codec_field", path.codec_field},
                    {"codec_rva", diagnostics::Hex(path.codec - module.address)},
                    {"characters_rva", diagnostics::Hex(path.characters - module.address)},
                    {"character_capture", false}});
            ReportProgram("weapon_name_data", path.object_offset / 8, path.data.code, module.address);
        }
    }
    if (!search.path) {
        evidence.extent = size;
        record(FeatureStatus::missing_path);
        feature_trace.Receiver(process, module, sections, native.metadata, Feature::weapon,
            FeatureStage::resource, 0, env.teb, 0, resource);
        return {};
    }
    const auto& path = *search.path;
    const auto object = resource + path.object_offset;
    if (Q(object) != path.object_vtable) {
        evidence.address = object;
        record(FeatureStatus::state_changed);
        search.path.reset();
        search.retry = {};
        return {};
    }
    cpu.Reset(env.teb);
    cpu.Set(ZYDIS_REGISTER_RCX, object);
    if (!trace.Run(cpu, path.data.code, "weapon_name_data", path.object_offset / 8, module.address)) {
        record(FeatureStatus::emulation_failed);
        return {};
    }
    const auto at = cpu.Get(path.data.output);
    const auto object_size = Extent(object, 0x10000);
    evidence.address = at;
    evidence.extent = object_size;
    if (at < object || at - object > object_size || object_size - (at - object) < 16) {
        record(FeatureStatus::extent_rejected);
        return {};
    }

    stage = FeatureStage::header;
    const auto string_header = Read<std::array<unsigned char, 16>>(at);
    Address data = at;
    std::uint32_t length{};
    if (string_header[0] || string_header[1] >= 4) {
        if (string_header[15] > 15) {
            record(FeatureStatus::invalid_layout);
            return {};
        }
        length = 15 - string_header[15];
    } else {
        std::uint16_t count{};
        std::memcpy(&count, string_header.data() + 2, 2);
        length = count;
        if (string_header[1] == 1) {
            const auto storage = Q(at + 8);
            if (count == 0xffff)
                length = Read<std::uint32_t>(storage + 4);
            data = storage + 0xa;
        } else if (string_header[1] == 2) {
            if (length > 10) {
                record(FeatureStatus::invalid_layout);
                return {};
            }
            data += 6;
        } else if (string_header[1] == 3)
            data = Q(at + 8);
        else {
            record(FeatureStatus::invalid_layout);
            return {};
        }
    }
    evidence.value = length;
    if (!length || length > 24) {
        record(FeatureStatus::invalid_value);
        return {};
    }
    stage = FeatureStage::text;
    const auto chars = Array<char>(data, length);
    std::string text(chars.begin(), chars.end());
    text.push_back('\0');
    auto name = equipment::WeaponName(text);
    stage = FeatureStage::snapshot;
    if (Q(resource) != table || Q(object) != path.object_vtable ||
        Read<std::array<unsigned char, 16>>(at) != string_header || Array<char>(data, length) != chars) {
        record(FeatureStatus::state_changed);
        return {};
    }
    record(name.empty() ? FeatureStatus::mapping_missing : FeatureStatus::ready);
    return name;
}

auto Reader::Implementation::WeaponFor(Address entity, CachedEntity& c, const Environment& env)
    -> std::string {
    FeatureEvidence evidence{.entity = entity, .receiver = c.team_source};
    auto stage = FeatureStage::component;
    const auto record = [&](FeatureStatus status) {
        feature_trace.Record(Feature::weapon, stage, status, evidence);
    };
    const auto now = std::chrono::steady_clock::now();
    try {
        if (now - c.weapon_at < std::chrono::milliseconds(100)) {
            stage = FeatureStage::owner;
            if (!c.weapon.empty() &&
                (!c.team_source || !c.component_count || c.team_source_index >= c.component_count ||
                    Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
                    (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) !=
                        c.component_count ||
                    Q(c.list + c.team_source_index * 8ull) != c.team_source ||
                    Hash(c.team_source) != 0xcdfd8752u)) {
                c.weapon.clear();
                stage = FeatureStage::owner;
                record(FeatureStatus::state_changed);
                return {};
            }
            evidence.value = c.weapon.size();
            stage = FeatureStage::value;
            record(c.weapon.empty() ? FeatureStatus::unavailable : FeatureStatus::cached);
            return c.weapon;
        }
        c.weapon_at = now;
        c.weapon.clear();
        if (!c.team_source) {
            record(FeatureStatus::missing_component);
            return {};
        }
        stage = FeatureStage::owner;
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list || !c.component_count ||
            c.team_source_index >= c.component_count ||
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
            Q(c.list + c.team_source_index * 8ull) != c.team_source || Hash(c.team_source) != 0xcdfd8752u) {
            record(FeatureStatus::state_changed);
            return {};
        }
        stage = FeatureStage::component;
        const auto parent = Q(c.team_source + 0x48);
        evidence.parent = parent;
        if (Hash(parent) == 0 || Extent(parent, 0x2000) < 0x40) {
            record(FeatureStatus::type_rejected);
            return {};
        }
        const auto parent_bytes = Array<std::byte>(parent, Extent(parent, 0x2000));
        Address component{}, list_field{}, list{};
        std::uint32_t count{};
        std::vector<Address> components;
        for (std::size_t field = 0; field + 16 <= parent_bytes.size(); field += 8) {
            Address candidate{}, flags{};
            std::memcpy(&candidate, parent_bytes.data() + field, 8);
            std::memcpy(&flags, parent_bytes.data() + field + 8, 8);
            const auto entries = static_cast<std::uint32_t>(flags & 0x3fffffffu);
            if (!Pointer(candidate) || !entries || entries >= 20)
                continue;
            try {
                const auto values = Array<Address>(candidate, entries);
                for (const auto value : values)
                    try {
                        if (Hash(value) != 0xe31d1e5bu)
                            continue;
                        if (component && component != value)
                            throw ReadFailure{ERROR_DUP_NAME};
                        if (!component) {
                            component = value;
                            list_field = field;
                            list = candidate;
                            count = entries;
                            components = values;
                        }
                    } catch (ReadFailure failure) {
                        if (failure.error == ERROR_DUP_NAME)
                            throw;
                    }
            } catch (ReadFailure failure) {
                if (failure.error == ERROR_DUP_NAME)
                    throw;
            }
        }
        if (!component) {
            record(FeatureStatus::missing_component);
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::weapon,
                FeatureStage::component, 0, env.teb, entity, c.team_source);
            return {};
        }
        evidence.receiver = component;
        stage = FeatureStage::discovery;
        const auto vtable = Q(component);
        auto found = weapon_paths.find(vtable);
        if (found == weapon_paths.end()) {
            std::optional<equipment::ResourcePath> accepted;
            std::set<Address> visited;
            for (const auto method : Array<Address>(vtable, 24))
                try {
                    if (!visited.insert(method).second)
                        continue;
                    const auto& code = EquipmentCode(method);
                    if (!code)
                        continue;
                    if (auto path = locators::WeaponResource(*code)) {
                        if (accepted)
                            throw ReadFailure{ERROR_DUP_NAME};
                        accepted = std::move(path);
                    }
                } catch (ReadFailure failure) {
                    if (failure.error == ERROR_DUP_NAME)
                        throw;
                }
            found = weapon_paths.emplace(vtable, std::move(accepted)).first;
            if (found->second) {
                const auto& path = *found->second;
                diagnostics::Write("weapon_resource_binding",
                    {{"entity", diagnostics::Hex(entity)}, {"component", diagnostics::Hex(component)},
                        {"vtable", diagnostics::Hex(vtable)}, {"field", path.field},
                        {"input", ZydisRegisterGetString(path.input)},
                        {"output", ZydisRegisterGetString(path.output)}});
                ReportProgram("weapon_resource", 0, path.code, module.address);
            }
        }
        if (!found->second) {
            record(FeatureStatus::missing_path);
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::weapon,
                FeatureStage::component, 0, env.teb, entity, component);
            return {};
        }
        const auto& path = *found->second;
        evidence.field = path.field;
        evidence.extent = Extent(component, 0x2000);
        if (path.field + 8 > evidence.extent) {
            record(FeatureStatus::extent_rejected);
            return {};
        }
        const auto encoded = Q(component + path.field);
        stage = FeatureStage::decode;
        cpu.Reset(env.teb);
        cpu.Set(path.input, component);
        if (!trace.Run(cpu, path.code, "weapon_resource", 0, module.address)) {
            record(FeatureStatus::emulation_failed);
            return {};
        }
        const auto holder = cpu.Get(path.output);
        evidence.value = holder;
        if (!Pointer(holder)) {
            record(holder ? FeatureStatus::invalid_value : FeatureStatus::uninitialized);
            return {};
        }
        stage = FeatureStage::resource;
        const auto resource = Q(holder);
        evidence.address = resource;
        evidence.expected = 0x740d1babu;
        evidence.observed = Hash(resource);
        if (evidence.observed != evidence.expected) {
            record(FeatureStatus::type_rejected);
            return {};
        }
        auto name = ResourceName(resource, env);
        if (name.empty())
            return {};
        stage = FeatureStage::snapshot;
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
            Q(c.list + c.team_source_index * 8ull) != c.team_source || Q(holder) != resource ||
            Q(component + path.field) != encoded || Q(component) != vtable ||
            Q(c.team_source + 0x48) != parent || Q(parent + list_field) != list ||
            (Read<std::uint32_t>(parent + list_field + 8) & 0x3fffffffu) != count ||
            Array<Address>(list, count) != components) {
            record(FeatureStatus::state_changed);
            return {};
        }
        c.weapon = std::move(name);
        evidence.value = c.weapon.size();
        record(FeatureStatus::ready);
    } catch (ReadFailure failure) {
        c.weapon.clear();
        evidence.win32 = failure.error;
        record(failure.error == ERROR_DUP_NAME     ? FeatureStatus::ambiguous_path
                : failure.error == ERROR_NOT_READY ? FeatureStatus::state_changed
                                                   : FeatureStatus::read_failed);
    }
    return c.weapon;
}
}
