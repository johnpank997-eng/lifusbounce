#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::DefuserFor(Address entity, const CachedEntity& c, const Environment& env)
    -> std::optional<bool> {
    if (!native.defuser || !c.local_role)
        return std::nullopt;
    try {
        const auto& path = *native.defuser;
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            Q(c.list + c.local_role_index * 8ull) != c.local_role || Hash(c.local_role) != 0xb8f1ea67u ||
            path.field >= Extent(c.local_role, 0x2000))
            return std::nullopt;
        const auto now = std::chrono::steady_clock::now();
        if (env.teb != defuser_teb || now - defuser_at >= std::chrono::milliseconds(100)) {
            defuser_values.reset();
            defuser_teb = env.teb;
            defuser_at = now;
            std::array<std::uint8_t, 2> values{};
            for (unsigned value = 0; value < 2; ++value) {
                cpu.Reset(env.teb);

                cpu.Set(path.object, cpu.Get(ZYDIS_REGISTER_RSP) + 0x4000);
                cpu.Set(path.input, value);
                if (!cpu.Run(path.encoder).Complete())
                    return std::nullopt;
                values[value] = static_cast<std::uint8_t>(cpu.Stack(0x4000 + path.field));
            }
            if (values[0] == values[1])
                return std::nullopt;
            defuser_values = values;
        }
        if (!defuser_values)
            return std::nullopt;
        const auto flag = Read<std::uint8_t>(c.local_role + path.field);
        if (Q(c.list + c.local_role_index * 8ull) != c.local_role ||
            Read<std::uint8_t>(c.local_role + path.field) != flag)
            return std::nullopt;
        if (flag == (*defuser_values)[0])
            return false;
        if (flag == (*defuser_values)[1])
            return true;
    } catch (ReadFailure) {
    }
    return std::nullopt;
}
}
