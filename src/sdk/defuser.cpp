#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::DefuserFor(Address entity, const CachedEntity& c, const Environment& env)
    -> std::optional<bool> {
    FeatureEvidence evidence{.entity = entity, .receiver = c.local_role};
    const auto record = [&](FeatureStage stage, FeatureStatus status) {
        feature_trace.Record(Feature::defuser, stage, status, evidence);
    };
    if (!native.defuser) {
        record(FeatureStage::discovery, FeatureStatus::missing_path);
        if (c.local_role)
            feature_trace.Receiver(process, module, sections, native.metadata, Feature::defuser,
                FeatureStage::discovery, 0, env.teb, entity, c.local_role);
        return std::nullopt;
    }
    if (!c.local_role) {
        record(FeatureStage::component, FeatureStatus::missing_component);
        return std::nullopt;
    }
    try {
        const auto& path = *native.defuser;
        evidence.field = path.field;
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list || !c.component_count ||
            c.local_role_index >= c.component_count ||
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
            Q(c.list + c.local_role_index * 8ull) != c.local_role) {
            record(FeatureStage::owner, FeatureStatus::state_changed);
            return std::nullopt;
        }
        evidence.expected = 0xb8f1ea67u;
        evidence.observed = Hash(c.local_role);
        if (evidence.observed != evidence.expected) {
            record(FeatureStage::component, FeatureStatus::type_rejected);
            return std::nullopt;
        }
        evidence.extent = Extent(c.local_role, 0x2000);
        if (path.field >= evidence.extent) {
            record(FeatureStage::flag, FeatureStatus::extent_rejected);
            return std::nullopt;
        }
        const auto now = std::chrono::steady_clock::now();
        if (env.teb != defuser_teb || now - defuser_at >= std::chrono::milliseconds(100)) {
            defuser_values.reset();
            defuser_teb = env.teb;
            defuser_at = now;
            std::array<std::uint8_t, 2> values{};
            for (unsigned value = 0; value < 2; ++value) {
                std::vector<Address> seeds;
                seeds.reserve(path.seeds.size());
                for (std::size_t i = 0; i < path.seeds.size(); ++i) {
                    const auto& seed = path.seeds[i];
                    const auto output =
                        ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, seed.output);
                    const auto target =
                        ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, seed.target);
                    if (ZydisRegisterGetClass(output) != ZYDIS_REGCLASS_GPR64 ||
                        output == ZYDIS_REGISTER_RSP ||
                        (seed.stack && (seed.slot < 0 || seed.slot >= 0x4000 || (seed.slot & 7))) ||
                        (!seed.stack &&
                            (ZydisRegisterGetClass(target) != ZYDIS_REGCLASS_GPR64 ||
                                target == ZYDIS_REGISTER_RSP))) {
                        evidence.path = i;
                        record(FeatureStage::decode, FeatureStatus::invalid_layout);
                        return std::nullopt;
                    }
                    cpu.Reset(env.teb);
                    if (!trace.Run(cpu, seed.code, "defuser_encoder_seed", value * 32 + i, module.address)) {
                        evidence.path = i;
                        record(FeatureStage::decode, FeatureStatus::emulation_failed);
                        return std::nullopt;
                    }
                    seeds.push_back(cpu.Get(seed.output));
                }
                cpu.Reset(env.teb);
                for (std::size_t i = 0; i < seeds.size(); ++i) {
                    const auto& seed = path.seeds[i];
                    if (seed.stack)
                        cpu.Stack(static_cast<std::uint32_t>(seed.slot), seeds[i]);
                    else
                        cpu.Set(seed.target, seeds[i]);
                }

                cpu.Set(path.object, cpu.Get(ZYDIS_REGISTER_RSP) + 0x4000);
                cpu.Set(path.input, value);
                if (!trace.Run(cpu, path.encoder, "defuser_encoder", value, module.address)) {
                    evidence.value = value;
                    record(FeatureStage::decode, FeatureStatus::emulation_failed);
                    return std::nullopt;
                }
                values[value] = static_cast<std::uint8_t>(cpu.Stack(0x4000 + path.field));
            }
            evidence.value = values[0];
            evidence.other = values[1];
            if (values[0] == values[1]) {
                record(FeatureStage::decode, FeatureStatus::invalid_value);
                return std::nullopt;
            }
            defuser_values = values;
        }
        if (!defuser_values) {
            record(FeatureStage::decode, FeatureStatus::unavailable);
            return std::nullopt;
        }
        const auto flag = Read<std::uint8_t>(c.local_role + path.field);
        evidence.address = c.local_role + path.field;
        evidence.value = flag;
        evidence.expected = (*defuser_values)[0];
        evidence.other = (*defuser_values)[1];
        if (Q(entity) != c.vtable || Q(entity + c.component_offset) != c.list ||
            (Read<std::uint32_t>(entity + c.component_offset + 8) & 0x3fffffffu) != c.component_count ||
            Q(c.list + c.local_role_index * 8ull) != c.local_role || Hash(c.local_role) != 0xb8f1ea67u ||
            Read<std::uint8_t>(c.local_role + path.field) != flag) {
            record(FeatureStage::flag, FeatureStatus::state_changed);
            return std::nullopt;
        }
        if (flag == (*defuser_values)[0]) {
            record(FeatureStage::flag, FeatureStatus::ready);
            return false;
        }
        if (flag == (*defuser_values)[1]) {
            record(FeatureStage::flag, FeatureStatus::ready);
            return true;
        }
        record(FeatureStage::flag, FeatureStatus::invalid_value);
    } catch (ReadFailure failure) {
        evidence.win32 = failure.error;
        record(FeatureStage::flag, FeatureStatus::read_failed);
        feature_trace.Receiver(process, module, sections, native.metadata, Feature::defuser,
            FeatureStage::component, 0, env.teb, entity, c.local_role);
    }
    return std::nullopt;
}
}
