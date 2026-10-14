#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::HealthFor(Address entity, CachedEntity& c, const Environment& env)
    -> std::optional<int> {
    if (native.health.size() != 1) {
        c.health.reset();
        feature_trace.Record(Feature::health, FeatureStage::discovery,
            native.health.empty() ? FeatureStatus::missing_path : FeatureStatus::ambiguous_path,
            {.entity = entity, .value = native.health.size()});
        feature_trace.Receiver(process, module, sections, native.metadata, Feature::health,
            FeatureStage::discovery, 0, env.teb, entity, entity);
        return std::nullopt;
    }
    const auto now = std::chrono::steady_clock::now();
    try {
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list) {
            c.health.reset();
            feature_trace.Record(Feature::health, FeatureStage::component, FeatureStatus::state_changed,
                {.entity = entity,
                    .receiver = c.list,
                    .field = static_cast<std::uint64_t>(c.component_offset)});
            return std::nullopt;
        }
        if (now - c.health_at < std::chrono::milliseconds(100)) {
            feature_trace.Record(Feature::health, FeatureStage::value,
                c.health ? FeatureStatus::cached : FeatureStatus::unavailable,
                {.entity = entity, .value = c.health ? static_cast<std::uint64_t>(*c.health) : 0});
            return c.health;
        }
        c.health_at = now;
        c.health.reset();
        const auto& path = native.health.front();
        cpu.Reset(env.teb);

        cpu.Stack(0, module.address);
        cpu.Set(ZYDIS_REGISTER_RCX, entity);
        cpu.Set(ZYDIS_REGISTER_RDX, entity);
        if (!trace.Run(cpu, path.code, "health_emulation_failed", 0, module.address)) {
            feature_trace.Record(
                Feature::health, FeatureStage::decode, FeatureStatus::emulation_failed, {.entity = entity});
            return std::nullopt;
        }
        const auto maximum = cpu.Get(path.maximum), current = cpu.Get(path.current);
        if (maximum <= 20 || maximum >= 300 || current >= 300) {
            feature_trace.Record(Feature::health, FeatureStage::value,
                !maximum && !current ? FeatureStatus::uninitialized : FeatureStatus::invalid_value,
                {.entity = entity, .value = current, .other = maximum});
            return std::nullopt;
        }
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list) {
            feature_trace.Record(Feature::health, FeatureStage::snapshot, FeatureStatus::state_changed,
                {.entity = entity, .receiver = c.list, .value = current, .other = maximum});
            return std::nullopt;
        }
        c.health = std::clamp(
            static_cast<int>((static_cast<float>(current) / static_cast<float>(maximum)) * 100.0f), 0, 100);
        feature_trace.Record(Feature::health, FeatureStage::value, FeatureStatus::ready,
            {.entity = entity,
                .value = current,
                .other = maximum,
                .observed = static_cast<std::uint64_t>(*c.health)});
    } catch (const ReadFailure& failure) {
        c.health.reset();
        feature_trace.Record(Feature::health, FeatureStage::decode, FeatureStatus::read_failed,
            {.entity = entity, .win32 = failure.error});
    }
    return c.health;
}
}
