#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::Discover(Address entity) -> CachedEntity {
    CachedEntity c{};
    c.vtable = Q(entity);
    c.expires = std::chrono::steady_clock::now() + std::chrono::milliseconds(2000 + (entity >> 4) % 500);
    const auto size = Extent(entity, 0x1000);
    const auto bytes = Array<std::byte>(entity, static_cast<std::size_t>(size));
    for (std::size_t i = 8; i + 8 <= bytes.size(); i += 8) {
        Address flags{};
        std::memcpy(&flags, bytes.data() + i, 8);
        const auto count = static_cast<std::uint32_t>(flags & 0x3fffffffull);
        if (count < 2 || count > 512)
            continue;
        try {
            const auto list = Q(entity + i - 8);
            if (!Pointer(list))
                continue;
            const auto components = Array<Address>(list, count);
            CachedEntity candidate{};
            candidate.vtable = c.vtable;
            candidate.expires = c.expires;
            candidate.component_offset = static_cast<std::int64_t>(i) - 8;
            candidate.list = list;
            candidate.component_count = count;
            for (std::uint32_t index = 0; index < components.size(); ++index)
                try {
                    const auto component = components[index];
                    const auto identity = Hash(component);
                    if (identity == 0x4e4b0976u) {
                        candidate.animation_component = component;
                        candidate.animation_index = index;
                    }
                    if (identity == 0x1d26c443u) {
                        candidate.transform_component = component;
                        candidate.transform_index = index;
                    }
                    if (identity == 0xb8f1ea67u) {
                        candidate.local_role = component;
                        candidate.local_role_index = index;
                    }
                    if (identity == 0xcdfd8752u) {
                        candidate.team_source = component;
                        candidate.team_source_index = index;
                    }
                    if (identity == 0xd1d46a6fu) {
                        candidate.username_component = component;
                        candidate.username_index = index;
                    }
                } catch (ReadFailure) {
                }
            if (!candidate.animation_component || !candidate.transform_component)
                continue;
            if (Q(entity + i - 8) != list || (Read<std::uint32_t>(entity + i) & 0x3fffffffu) != count ||
                Array<Address>(list, count) != components)
                throw ReadFailure{ERROR_NOT_READY};
            if (c.list &&
                (c.animation_component != candidate.animation_component ||
                    c.transform_component != candidate.transform_component ||
                    (c.username_component && candidate.username_component &&
                        c.username_component != candidate.username_component)))
                throw ReadFailure{ERROR_DUP_NAME};
            const auto roles = [](const CachedEntity& v) {
                return unsigned(bool(v.local_role)) + unsigned(bool(v.username_component));
            };
            if (!c.list || roles(candidate) > roles(c))
                c = std::move(candidate);
        } catch (ReadFailure failure) {
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    }
    if (!c.animation_component || !c.transform_component)
        c.expires = std::chrono::steady_clock::now() + std::chrono::milliseconds(100 + (entity >> 4) % 25);
    c.next_components = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    return c;
}
}
