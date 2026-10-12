#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::ProfileFor(Address entity, CachedEntity& c, const Environment& env) -> Address {
    if (!c.username_component || native.usernames.size() != 1)
        return 0;
    if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
        Q(c.list + c.username_index * 8ull) != c.username_component ||
        Hash(c.username_component) != 0xd1d46a6fu) {
        c.username_component = c.name_profile = c.profile = 0;
        c.username.clear();
        c.affiliation_path.reset();
        c.next_components = {};
        return 0;
    }
    const auto now = std::chrono::steady_clock::now();
    if (c.profile && now - c.profile_at < std::chrono::milliseconds(30))
        return c.profile;
    c.profile = 0;
    const auto& path = native.usernames.front();
    const auto matches = [&](Address object, Address expected) {
        const auto range = Read<std::array<std::uint16_t, 2>>(TypeInfo(object) + 0x40);
        const auto base = Read<std::array<std::uint16_t, 2>>(expected);
        return range[0] >= base[0] && range[1] <= base[1];
    };
    cpu.Reset(env.teb);
    cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
    if (!cpu.Run(path.owner.code).Complete())
        return 0;
    const auto owner = cpu.Get(path.owner.output);
    if (!Pointer(owner) || !matches(owner, path.owner_type))
        return 0;
    cpu.Reset(env.teb);
    cpu.Set(path.owner.output, owner);
    if (!cpu.Run(path.profile.code).Complete())
        return 0;
    const auto profile = cpu.Get(path.profile.output);
    if (!Pointer(profile) || !matches(profile, path.profile_type) ||
        Q(c.list + c.username_index * 8ull) != c.username_component)
        return 0;
    c.profile = profile;
    c.profile_at = now;
    return profile;
}

auto Reader::Implementation::UsernameFor(Address entity, CachedEntity& c, const Environment& env)
    -> std::string {
    if (!c.username_component || native.usernames.size() != 1)
        return {};
    const auto now = std::chrono::steady_clock::now();
    try {
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            Q(c.list + c.username_index * 8ull) != c.username_component ||
            Hash(c.username_component) != 0xd1d46a6fu) {
            c.username_component = c.name_profile = c.profile = 0;
            c.username.clear();
            c.affiliation_path.reset();
            c.next_components = {};
            return {};
        }
        if (now - c.username_at < std::chrono::seconds(1))
            return c.username;
        c.username_at = now;
        const auto& path = native.usernames.front();
        const auto matches = [&](Address object, Address expected) {
            const auto info = TypeInfo(object);
            const auto range = Read<std::array<std::uint16_t, 2>>(info + 0x40);
            const auto base = Read<std::array<std::uint16_t, 2>>(expected);
            return range[0] >= base[0] && range[1] <= base[1];
        };
        const auto resolve_name = [&]() {
            cpu.Reset(env.teb);
            cpu.Set(ZYDIS_REGISTER_RDX, c.username_component);
            if (!cpu.Run(path.owner.code).Complete())
                throw ReadFailure{ERROR_NOT_READY};
            const auto owner = cpu.Get(path.owner.output);
            const bool ai_owner = Hash(owner) == 0xc812b23du;
            if (!ai_owner && !matches(owner, path.owner_type))
                throw ReadFailure{ERROR_INVALID_DATA};
            cpu.Reset(env.teb);
            cpu.Set(path.owner.output, owner);
            if (!cpu.Run(path.profile.code).Complete())
                throw ReadFailure{ERROR_NOT_READY};
            const auto profile = cpu.Get(path.profile.output);

            if (ai_owner ? Hash(profile) != 0x5d19580bu : !matches(profile, path.profile_type))
                throw ReadFailure{ERROR_INVALID_DATA};
            return profile;
        };
        const auto profile = resolve_name();

        const auto field = path.string_field;
        if (field + 16 > Extent(profile, 0x10000))
            throw ReadFailure{ERROR_INVALID_DATA};
        const auto string_header = Read<std::array<unsigned char, 16>>(profile + field);
        Address data = profile + field;
        std::uint32_t length{};
        if (string_header[0] || string_header[1] >= 4) {
            if (string_header[15] > 15)
                throw ReadFailure{ERROR_INVALID_DATA};
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
                    throw ReadFailure{ERROR_INVALID_DATA};
                data += 6;
            } else if (string_header[1] == 3)
                data = Q(profile + field + 8);
            else
                throw ReadFailure{ERROR_INVALID_DATA};
        }
        if (!length || length > 256)
            throw ReadFailure{ERROR_INVALID_DATA};
        const auto text = Array<char>(data, length);
        if (std::any_of(text.begin(), text.end(), [](unsigned char ch) { return ch < 32 || ch == 127; }) ||
            !MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0) ||
            resolve_name() != profile ||
            Read<std::array<unsigned char, 16>>(profile + field) != string_header ||
            Q(c.list + c.username_index * 8ull) != c.username_component)
            throw ReadFailure{ERROR_INVALID_DATA};
        c.username.assign(text.begin(), text.end());
        c.name_profile = profile;
    } catch (ReadFailure) {
        c.username.clear();
        c.name_profile = 0;
    }
    return c.username;
}
}
