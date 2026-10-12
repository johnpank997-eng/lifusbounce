#include "sdk/reader_internal.hpp"

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
                                if (!cpu.Run(member.descriptor.code).Complete())
                                    continue;
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
                                if (!cpu.Run(member.data.code).Complete())
                                    continue;
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
    }
    if (!search.path)
        return {};
    const auto& path = *search.path;
    const auto object = resource + path.object_offset;
    if (Q(object) != path.object_vtable) {
        search.path.reset();
        search.retry = {};
        return {};
    }
    cpu.Reset(env.teb);
    cpu.Set(ZYDIS_REGISTER_RCX, object);
    if (!cpu.Run(path.data.code).Complete())
        return {};
    const auto at = cpu.Get(path.data.output);
    const auto object_size = Extent(object, 0x10000);
    if (at < object || at - object > object_size || object_size - (at - object) < 16)
        return {};

    const auto string_header = Read<std::array<unsigned char, 16>>(at);
    Address data = at;
    std::uint32_t length{};
    if (string_header[0] || string_header[1] >= 4) {
        if (string_header[15] > 15)
            return {};
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
            if (length > 10)
                return {};
            data += 6;
        } else if (string_header[1] == 3)
            data = Q(at + 8);
        else
            return {};
    }
    if (!length || length > 24)
        return {};
    const auto chars = Array<char>(data, length);
    std::string text(chars.begin(), chars.end());
    text.push_back('\0');
    auto name = equipment::WeaponName(text);
    if (Q(resource) != table || Q(object) != path.object_vtable ||
        Read<std::array<unsigned char, 16>>(at) != string_header || Array<char>(data, length) != chars)
        return {};
    return name;
}

auto Reader::Implementation::WeaponFor(Address entity, CachedEntity& c, const Environment& env)
    -> std::string {
    const auto now = std::chrono::steady_clock::now();
    if (now - c.weapon_at < std::chrono::milliseconds(100))
        return c.weapon;
    c.weapon_at = now;
    c.weapon.clear();
    try {
        if (!c.team_source || Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            Q(c.list + c.team_source_index * 8ull) != c.team_source || Hash(c.team_source) != 0xcdfd8752u)
            return {};
        const auto parent = Q(c.team_source + 0x48);
        if (Hash(parent) == 0 || Extent(parent, 0x2000) < 0x40)
            return {};
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
        if (!component)
            return {};
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
        }
        if (!found->second || found->second->field + 8 > Extent(component, 0x2000))
            return {};
        const auto& path = *found->second;
        const auto encoded = Q(component + path.field);
        cpu.Reset(env.teb);
        cpu.Set(path.input, component);
        if (!cpu.Run(path.code).Complete())
            return {};
        const auto holder = cpu.Get(path.output);
        if (!Pointer(holder))
            return {};
        const auto resource = Q(holder);
        if (Hash(resource) != 0x740d1babu)
            return {};
        auto name = ResourceName(resource, env);
        if (name.empty() || Q(holder) != resource || Q(component + path.field) != encoded ||
            Q(component) != vtable || Q(c.team_source + 0x48) != parent || Q(parent + list_field) != list ||
            (Read<std::uint32_t>(parent + list_field + 8) & 0x3fffffffu) != count ||
            Array<Address>(list, count) != components)
            return {};
        c.weapon = std::move(name);
    } catch (ReadFailure) {
    }
    return c.weapon;
}
}
