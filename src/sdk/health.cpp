#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::HealthFor(Address entity, CachedEntity& c, const Environment& env)
    -> std::optional<int> {
    if (native.health.size() != 1)
        return std::nullopt;
    const auto now = std::chrono::steady_clock::now();
    if (now - c.health_at < std::chrono::milliseconds(100))
        return c.health;
    c.health_at = now;
    c.health.reset();
    try {
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list)
            return std::nullopt;
        const auto& path = native.health.front();
        cpu.Reset(env.teb);

        cpu.Stack(0, module.address);
        cpu.Set(ZYDIS_REGISTER_RCX, entity);
        cpu.Set(ZYDIS_REGISTER_RDX, entity);
        const auto evaluated = cpu.Run(path.code);
        if (!evaluated.Complete())
            return std::nullopt;
        const auto maximum = cpu.Get(path.maximum), current = cpu.Get(path.current);

        if (maximum > 20 && maximum < 300 && current < 300 && Q(entity) == c.vtable &&
            Q(entity + c.component_offset) == c.list)
            c.health = std::clamp(
                static_cast<int>((static_cast<float>(current) / static_cast<float>(maximum)) * 100.0f), 0,
                100);
    } catch (ReadFailure) {
    }
    return c.health;
}
}
