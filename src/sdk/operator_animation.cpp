#include "sdk/operator_animation.hpp"

namespace base::sdk::operators {
static bool Ordinary(const Emulator::Decoded& d, const ZydisDecodedOperand& operand) {
    return d.instruction.address_width == 64 && operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operand.mem.type == ZYDIS_MEMOP_TYPE_MEM && operand.mem.segment != ZYDIS_REGISTER_FS &&
        operand.mem.segment != ZYDIS_REGISTER_GS;
}

static std::optional<std::vector<bool>> CollectionRegion(const Emulator::Program& code, std::size_t begin,
    std::size_t end, const std::vector<std::vector<std::size_t>>& edges) {
    const auto& ins = code.instructions;
    if (begin >= ins.size() || end >= ins.size() || edges.size() != ins.size())
        return std::nullopt;
    std::vector<bool> seen(ins.size());
    std::vector<std::size_t> pending{begin};
    while (!pending.empty()) {
        const auto i = pending.back();
        pending.pop_back();
        if (i >= ins.size() || seen[i])
            continue;
        seen[i] = true;
        if (i == end || ins[i].instruction.meta.category == ZYDIS_CATEGORY_RET)
            continue;
        pending.insert(pending.end(), edges[i].begin(), edges[i].end());
    }
    if (!seen[end])
        return std::nullopt;
    seen[end] = false;
    return seen;
}

bool Reg(const ZydisDecodedOperand& operand, ZydisRegister value) {
    return operand.type == ZYDIS_OPERAND_TYPE_REGISTER && operand.reg.value == value;
}

std::optional<std::uint64_t> ReceiverCall(const Emulator::Program& method) {
    for (std::size_t i = 0; i < std::min<std::size_t>(24, method.instructions.size()); ++i) {
        const auto& d = method.instructions[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_CALL) {
            std::uint64_t target{};
            if (d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &d.operands[0], d.address, &target)))
                return target;
            return std::nullopt;
        }
        if (d.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            d.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            return std::nullopt;
        for (unsigned k = 0; k < d.instruction.operand_count; ++k) {
            const auto& o = d.operands[k];
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER && (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, o.reg.value) ==
                    ZYDIS_REGISTER_RCX)
                return std::nullopt;
        }
    }
    return std::nullopt;
}

static std::optional<ModuleLayout> ModuleLayoutFor(const Emulator::Program& code, bool expanded,
    const std::function<std::optional<std::int32_t>(std::uint64_t)>& read, ModuleDiscovery* discovery,
    std::uint64_t source_end) {
    if (discovery)
        *discovery = {ModuleRejection::receiver};
    const auto& ins = code.instructions;
    ZydisRegister receiver = ZYDIS_REGISTER_NONE;
    std::size_t receiver_begin{};
    for (std::size_t i = 0; i < std::min<std::size_t>(24, ins.size()); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 64 &&
            Reg(d.operands[1], ZYDIS_REGISTER_RCX)) {
            if (receiver != ZYDIS_REGISTER_NONE)
                return std::nullopt;
            receiver = d.operands[0].reg.value;
            receiver_begin = i;
        }
    }
    if (receiver == ZYDIS_REGISTER_NONE)
        return std::nullopt;
    if (discovery)
        discovery->rejection = ModuleRejection::aliases;
    std::optional<std::size_t> complete;
    for (std::size_t i = 1; i < ins.size(); ++i)
        if (ins[i].instruction.mnemonic == ZYDIS_MNEMONIC_MOV && Ordinary(ins[i], ins[i].operands[0]) &&
            ins[i].operands[0].size == 32 && ins[i].operands[0].mem.base != ZYDIS_REGISTER_RSP &&
            ins[i].operands[0].mem.base != ZYDIS_REGISTER_RIP &&
            ins[i].operands[0].mem.index == ZYDIS_REGISTER_NONE && ins[i].operands[0].mem.disp.value >= 0 &&
            ins[i].operands[0].mem.disp.value <= 0x10000 && Reg(ins[i].operands[1], ZYDIS_REGISTER_EAX) &&
            ((i > 2 && ins[i - 1].instruction.mnemonic == ZYDIS_MNEMONIC_NOT &&
                 Reg(ins[i - 1].operands[0], ZYDIS_REGISTER_EAX) &&
                 ins[i - 2].instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                 ins[i - 3].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                 Reg(ins[i - 3].operands[0], ZYDIS_REGISTER_EDX) &&
                 ins[i - 3].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                 std::uint32_t(ins[i - 3].operands[1].imm.value.u) == 0xffffffffu) ||
                (i > 3 && ins[i - 1].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    ins[i - 2].instruction.mnemonic == ZYDIS_MNEMONIC_NOT &&
                    Reg(ins[i - 2].operands[0], ZYDIS_REGISTER_EAX) &&
                    ins[i - 3].instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
                    ins[i - 4].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    Reg(ins[i - 4].operands[0], ZYDIS_REGISTER_EDX) &&
                    ins[i - 4].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                    std::uint32_t(ins[i - 4].operands[1].imm.value.u) == 0xffffffffu)))
            complete = i;
    std::vector<std::vector<std::size_t>> edges;
    std::vector<std::array<std::optional<std::uint64_t>, 16>> values;
    std::vector<std::map<std::int64_t, std::uint64_t>> locals;
    std::vector<StackProvenance> provenance;
    const auto bindings = complete ? ReceiverBindings(code, receiver_begin, *complete, read, source_end,
                                         &edges, &values, &locals, &provenance)
                                   : std::vector<std::uint16_t>{};
    if (expanded && bindings.empty())
        return std::nullopt;
    if (discovery)
        discovery->rejection = ModuleRejection::checksum;
    const auto owned = [&](std::size_t i, ZydisRegister base) {
        if (!expanded)
            return base == receiver;
        const auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, base);
        return i < bindings.size() && largest >= ZYDIS_REGISTER_RAX && largest <= ZYDIS_REGISTER_R15 &&
            (bindings[i] & (1u << (largest - ZYDIS_REGISTER_RAX)));
    };
    const auto constant = [&](std::size_t at, const ZydisDecodedOperand& operand,
                              unsigned bits = 0) -> std::optional<std::uint64_t> {
        if (!bits)
            bits = operand.size;
        const auto width = bits == 32 ? 0xffffffffull : bits == 64 ? ~0ull : 0;
        if (!width)
            return std::nullopt;
        if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            return operand.imm.value.u & width;
        if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RSP &&
            operand.mem.index == ZYDIS_REGISTER_NONE && operand.mem.segment != ZYDIS_REGISTER_FS &&
            operand.mem.segment != ZYDIS_REGISTER_GS && at < locals.size())
            if (const auto found = locals[at].find(operand.mem.disp.value); found != locals[at].end())
                return found->second & width;
        const auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, operand.reg.value);
        if (operand.type != ZYDIS_OPERAND_TYPE_REGISTER || at >= values.size() ||
            largest < ZYDIS_REGISTER_RAX || largest > ZYDIS_REGISTER_R15)
            return std::nullopt;
        const auto value = values[at][largest - ZYDIS_REGISTER_RAX];
        return value ? std::optional<std::uint64_t>(*value & width) : std::nullopt;
    };

    struct Store {
        std::size_t instruction;
        std::uint32_t field;
        std::uint64_t crc;
        std::size_t write;
    };

    std::vector<Store> stores;
    for (std::size_t i = 1; i + 2 < ins.size(); ++i) {
        const auto& call = ins[i];
        const auto& inverse = ins[i + 1];
        auto write_index = i + 2;
        if (expanded && ins[write_index].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            ins[write_index].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[write_index].operands[0].size == 64 &&
            ins[write_index].operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            ins[write_index].operands[1].mem.base == ZYDIS_REGISTER_RSP &&
            ins[write_index].operands[1].mem.index == ZYDIS_REGISTER_NONE) {
            if (write_index + 1 >= ins.size() ||
                !owned(write_index + 1, ins[write_index].operands[0].reg.value))
                continue;
            ++write_index;
        }
        if (write_index >= ins.size())
            continue;
        const auto& write = ins[write_index];
        if (call.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            call.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            inverse.instruction.mnemonic != ZYDIS_MNEMONIC_NOT ||
            !Reg(inverse.operands[0], ZYDIS_REGISTER_EAX) ||
            write.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || !Reg(write.operands[1], ZYDIS_REGISTER_EAX))
            continue;
        const auto& target = write.operands[0];
        const auto& seed = ins[i - 1];
        if (!Ordinary(write, target) || target.size != 32 || !owned(write_index, target.mem.base) ||
            target.mem.index != ZYDIS_REGISTER_NONE || target.mem.disp.value < 0 ||
            target.mem.disp.value > 0x10000 || seed.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            !Reg(seed.operands[0], ZYDIS_REGISTER_EDX) ||
            seed.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            static_cast<std::uint32_t>(seed.operands[1].imm.value.u) != 0xffffffffu)
            continue;
        std::uint64_t crc{};
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&call.instruction, &call.operands[0], call.address, &crc)))
            stores.push_back({i, static_cast<std::uint32_t>(target.mem.disp.value), crc, write_index});
    }
    if (discovery)
        discovery->stores = stores.size();
    if (stores.size() < 4 || stores[stores.size() - 2].crc != stores.back().crc ||
        stores[stores.size() - 2].field == stores.back().field ||
        (expanded && stores.back().write != complete))
        return std::nullopt;
    if (discovery) {
        discovery->stores = stores.size();
        discovery->rejection = ModuleRejection::collection;
    }
    const auto checksum = stores[stores.size() - 2];
    const auto collection_begin =
        expanded ? stores[stores.size() - 3].write + 1 : stores[stores.size() - 3].instruction + 3;
    const auto region = expanded ? CollectionRegion(code, collection_begin, checksum.instruction, edges)
                                 : std::optional<std::vector<bool>>{};
    if (expanded && !region)
        return std::nullopt;

    struct Count {
        std::uint64_t mask{};
        std::uint32_t width{}, shift{};
        std::uint64_t consumer{}, direct{}, store{};
        std::int64_t slot{};
        std::uint64_t byte_mask{};
        std::uint32_t direct_width{}, direct_shift{};
    };

    using CountKey = std::tuple<std::uint32_t, std::uint32_t, std::uint32_t>;
    std::map<CountKey, Count> semantics;
    std::map<std::uint32_t, Count> arrays;
    std::set<CountKey> conflicting;
    for (std::size_t i = 0; i + 2 < ins.size(); ++i) {
        const auto& d = ins[i];
        const auto& source = d.operands[1];
        const auto& shift = ins[i + 1];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            (d.operands[0].size != 32 && d.operands[0].size != 64) || !Ordinary(d, source) ||
            !owned(i, source.mem.base) || source.mem.index != ZYDIS_REGISTER_NONE ||
            source.mem.disp.value < 8 || source.mem.disp.value > 0x10000 ||
            (source.size != 32 && source.size != 64) || shift.instruction.mnemonic != ZYDIS_MNEMONIC_SHL ||
            shift.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            (shift.operands[0].size != 32 && shift.operands[0].size != 64) ||
            ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, shift.operands[0].reg.value) !=
                ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, d.operands[0].reg.value) ||
            shift.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || shift.operands[1].imm.value.u != 3)
            continue;
        const auto field = static_cast<std::uint32_t>(source.mem.disp.value);
        if (source.size == 32 && shift.operands[0].size == 32 &&
            ins[i + 2].instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
            Reg(ins[i + 2].operands[0], shift.operands[0].reg.value) &&
            Reg(ins[i + 2].operands[1], shift.operands[0].reg.value) && i + 4 < ins.size()) {
            const auto& branch = ins[i + 3];
            std::uint64_t target{};
            if ((branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ ||
                    branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ) &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &branch.instruction, &branch.operands[0], branch.address, &target))) {
                const auto pointer = branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ
                    ? ins.begin() + i + 4
                    : std::lower_bound(ins.begin(), ins.end(), target,
                          [](const auto& instruction, std::uint64_t at) { return instruction.address < at; });
                if (pointer != ins.end() && pointer + 1 != ins.end() &&
                    pointer->instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    pointer->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    pointer->operands[0].size == 64 && Ordinary(*pointer, pointer->operands[1]) &&
                    pointer->operands[1].size == 64 &&
                    owned(pointer - ins.begin(), pointer->operands[1].mem.base) &&
                    pointer->operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                    pointer->operands[1].mem.disp.value == field - 8 &&
                    (pointer + 1)->instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                    (pointer + 1)->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (pointer + 1)->operands[0].size == 64 &&
                    ZydisRegisterGetLargestEnclosing(
                        ZYDIS_MACHINE_MODE_LONG_64, (pointer + 1)->operands[0].reg.value) ==
                        ZydisRegisterGetLargestEnclosing(
                            ZYDIS_MACHINE_MODE_LONG_64, d.operands[0].reg.value) &&
                    Reg((pointer + 1)->operands[1], pointer->operands[0].reg.value)) {
                    const CountKey key{field, 32, 32};
                    const auto [found, inserted] = semantics.emplace(
                        key, Count{0x1fffffff, 32, 32, d.address, d.address, 0, 0, 0xfffffff8});
                    if (!inserted && found->second.mask != 0x1fffffff)
                        conflicting.insert(key);
                }
            }
        }
        for (std::size_t at = i + 2; at < std::min(ins.size(), i + 10); ++at) {
            const auto& mask = ins[at];
            if (mask.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
                mask.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
                mask.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
                break;
            if (mask.instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
                Reg(mask.operands[0], shift.operands[0].reg.value) &&
                mask.operands[0].size == shift.operands[0].size) {
                const auto value = mask.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY
                    ? constant(at, mask.operands[1], mask.operands[0].size)
                    : std::nullopt;
                if (!value)
                    break;
                const auto count_mask = (*value >> 3) & (source.size == 32 ? 0xffffffffull : ~0ull) &
                    (shift.operands[0].size == 32 ? 0x1fffffffull : 0x1fffffffffffffffull);
                if (count_mask < 63 || count_mask > 0x3fffffff || (count_mask & (count_mask + 1)))
                    break;
                Count candidate{count_mask, source.size, shift.operands[0].size, d.address, d.address};
                candidate.byte_mask = *value;
                for (auto store = i + 2; store < at; ++store) {
                    const auto& write = ins[store];
                    const auto stored = constant(store, write.operands[1], 64);
                    if (write.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                        write.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && write.operands[0].size == 64 &&
                        write.operands[0].mem.base == ZYDIS_REGISTER_RSP &&
                        write.operands[0].mem.index == ZYDIS_REGISTER_NONE && stored == value) {
                        candidate.store = write.address;
                        candidate.slot = write.operands[0].mem.disp.value;
                    }
                }
                const CountKey key{field, candidate.width, candidate.shift};
                const auto [found, inserted] = semantics.emplace(key, candidate);
                if (!inserted &&
                    (found->second.mask != candidate.mask || found->second.width != candidate.width ||
                        found->second.shift != candidate.shift))
                    conflicting.insert(key);
                else if (!inserted && !found->second.store && candidate.store)
                    found->second = candidate;
                break;
            }
            bool changed{};
            for (const auto& operand : mask.operands)
                changed |= operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, operand.reg.value) ==
                        ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, d.operands[0].reg.value);
            if (changed)
                break;
        }
    }
    std::set<std::uint32_t> primary;
    bool count_ambiguous{};
    const auto array = [&](std::uint32_t field, Count count) {
        if (conflicting.contains({field + 8, count.width, count.shift}) || count.mask < 63 ||
            (count.mask & (count.mask + 1)) || count.mask > 0x3fffffff)
            return;
        const auto [found, inserted] = arrays.emplace(field, count);
        count_ambiguous |= !inserted &&
            (found->second.mask != count.mask || found->second.width != count.width ||
                found->second.shift != count.shift);
    };
    const auto vector_bound = [&](std::size_t begin, ZydisRegister counter, std::uint32_t field) {
        const auto bit = [](ZydisRegister reg) -> std::uint16_t {
            const auto parent = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
            return parent >= ZYDIS_REGISTER_RAX && parent <= ZYDIS_REGISTER_R15
                ? static_cast<std::uint16_t>(1u << (parent - ZYDIS_REGISTER_RAX))
                : 0;
        };
        struct State {
            std::size_t at;
            std::uint16_t count, vector;
        };
        std::vector<State> pending{{begin, bit(counter), 0}};
        std::vector<std::set<std::pair<std::uint16_t, std::uint16_t>>> visited(ins.size());
        unsigned states{};
        while (!pending.empty()) {
            const auto state = pending.back();
            pending.pop_back();
            if (state.at >= ins.size() || !state.count ||
                !visited[state.at].emplace(state.count, state.vector).second)
                continue;
            if (++states > 0x4000)
                return false;
            const auto& d = ins[state.at];
            const auto& destination = d.operands[0];
            const auto& source = d.operands[1];
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                destination.type == ZYDIS_OPERAND_TYPE_REGISTER && destination.size == 64 &&
                source.type == ZYDIS_OPERAND_TYPE_REGISTER && source.size == 64 &&
                (state.count & bit(destination.reg.value)) && (state.vector & bit(source.reg.value)))
                return true;
            auto count = state.count, vector = state.vector;
            for (const auto& operand : d.operands)
                if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)) {
                    count &= ~bit(operand.reg.value);
                    vector &= ~bit(operand.reg.value);
                }
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                destination.type == ZYDIS_OPERAND_TYPE_REGISTER && destination.size == 64) {
                if (source.type == ZYDIS_OPERAND_TYPE_REGISTER && source.size == 64) {
                    if (state.count & bit(source.reg.value))
                        count |= bit(destination.reg.value);
                    if (state.vector & bit(source.reg.value))
                        vector |= bit(destination.reg.value);
                } else if (Ordinary(d, source) && source.size == 64 &&
                    source.mem.index == ZYDIS_REGISTER_NONE && source.mem.disp.value == field &&
                    owned(state.at, source.mem.base))
                    vector |= bit(destination.reg.value);
            }
            if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL) {
                constexpr std::uint16_t volatile_registers = 0xf07;
                count &= ~volatile_registers;
                vector &= ~volatile_registers;
            }
            for (const auto next : edges[state.at])
                pending.push_back({next, count, vector});
        }
        return false;
    };
    for (std::size_t i = collection_begin; i + 3 < checksum.instruction; ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || !Ordinary(d, d.operands[1]) ||
            !owned(i, d.operands[1].mem.base) || d.operands[1].mem.index != ZYDIS_REGISTER_NONE ||
            d.operands[1].mem.disp.value < 8 || d.operands[1].mem.disp.value > 0x10000)
            continue;
        const auto field = static_cast<std::uint32_t>(d.operands[1].mem.disp.value);
        if (d.operands[1].size == 32 || d.operands[1].size == 64) {
            const auto& shift = ins[i + 1];
            const auto& mask = ins[i + 2];
            if (shift.instruction.mnemonic == ZYDIS_MNEMONIC_SHL &&
                Reg(shift.operands[0], d.operands[0].reg.value) &&
                shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                shift.operands[1].imm.value.u == 3 && mask.instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
                Reg(mask.operands[0], d.operands[0].reg.value) &&
                shift.operands[0].size == d.operands[0].size &&
                mask.operands[0].size == shift.operands[0].size) {
                if (!vector_bound(i + 3, d.operands[0].reg.value, field - 8))
                    continue;
                const auto value = constant(i + 2, mask.operands[1], mask.operands[0].size);
                if (value) {
                    array(field - 8,
                        {(*value >> 3) & (d.operands[1].size == 32 ? 0xffffffffull : ~0ull) &
                                (shift.operands[0].size == 32 ? 0x1fffffffull : 0x1fffffffffffffffull),
                            d.operands[1].size, shift.operands[0].size, d.address, d.address});
                } else if (i + 2 < provenance.size()) {
                    std::optional<std::int64_t> slot;
                    const auto& operand = mask.operands[1];
                    if (Ordinary(mask, operand) && operand.size == 64 &&
                        operand.mem.base == ZYDIS_REGISTER_RSP && operand.mem.index == ZYDIS_REGISTER_NONE)
                        slot = operand.mem.disp.value;
                    else if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER && operand.size == 64) {
                        const auto reg =
                            ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, operand.reg.value);
                        if (reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15)
                            slot = provenance[i + 2].sources[reg - ZYDIS_REGISTER_RAX];
                    }
                    const auto assignment = slot ? provenance[i + 2].assignments.find(*slot)
                                                 : provenance[i + 2].assignments.end();
                    if (assignment != provenance[i + 2].assignments.end())
                        for (const auto& [key, direct] : semantics)
                            if (std::get<0>(key) == field && !conflicting.contains(key)) {
                                const auto actual = (assignment->second.first >> 3) &
                                    (d.operands[1].size == 32 ? 0xffffffffull : ~0ull) &
                                    (shift.operands[0].size == 32 ? 0x1fffffffull : 0x1fffffffffffffffull);
                                if (actual != direct.mask) {
                                    count_ambiguous = true;
                                    continue;
                                }
                                auto count = direct;
                                count.direct_width = direct.width;
                                count.direct_shift = direct.shift;
                                count.consumer = d.address;
                                count.width = d.operands[1].size;
                                count.shift = shift.operands[0].size;
                                count.store = assignment->second.second;
                                count.slot = *slot;
                                count.byte_mask = assignment->second.first;
                                array(field - 8, count);
                            }
                }
            } else if (expanded && d.operands[0].size == 32 &&
                shift.instruction.mnemonic == ZYDIS_MNEMONIC_SHL &&
                Reg(shift.operands[0], d.operands[0].reg.value) && shift.operands[0].size == 32 &&
                shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                shift.operands[1].imm.value.u == 3 && mask.instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
                Reg(mask.operands[0], d.operands[0].reg.value) &&
                Reg(mask.operands[1], d.operands[0].reg.value) && i + 3 < ins.size()) {
                const auto& branch = ins[i + 3];
                if (branch.instruction.mnemonic != ZYDIS_MNEMONIC_JZ &&
                    branch.instruction.mnemonic != ZYDIS_MNEMONIC_JNZ)
                    continue;
                std::uint64_t target{};
                if (branch.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                    !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                        &branch.instruction, &branch.operands[0], branch.address, &target)))
                    continue;
                auto pointer = branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ
                    ? ins.begin() + i + 4
                    : std::lower_bound(ins.begin(), ins.end(), target,
                          [](const auto& instruction, std::uint64_t at) { return instruction.address < at; });
                if (pointer == ins.end() ||
                    (branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ && pointer->address != target))
                    continue;
                if (pointer->instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    pointer->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    pointer->operands[0].size == 64 && Ordinary(*pointer, pointer->operands[1]) &&
                    pointer->operands[1].size == 64 &&
                    owned(pointer - ins.begin(), pointer->operands[1].mem.base) &&
                    pointer->operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                    pointer->operands[1].mem.disp.value == field - 8 && pointer + 1 != ins.end() &&
                    (pointer + 1)->instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                    (pointer + 1)->operands[0].size == 64 && (pointer + 1)->operands[1].size == 64 &&
                    ZydisRegisterGetLargestEnclosing(
                        ZYDIS_MACHINE_MODE_LONG_64, (pointer + 1)->operands[0].reg.value) ==
                        ZydisRegisterGetLargestEnclosing(
                            ZYDIS_MACHINE_MODE_LONG_64, d.operands[0].reg.value) &&
                    Reg((pointer + 1)->operands[1], pointer->operands[0].reg.value))
                    array(field - 8, {0x1fffffff, 32, 32, d.address, d.address});
            }
        }
        if (d.operands[1].size == 64) {
            const auto wrapper = d.operands[0].reg.value;
            bool data{}, flags{};
            for (std::size_t k = i + 1; k < std::min(checksum.instruction, i + 24); ++k) {
                const auto& load = ins[k];
                if (load.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && Ordinary(load, load.operands[1]) &&
                    load.operands[1].mem.base == wrapper && load.operands[1].mem.disp.value == 0 &&
                    load.operands[1].mem.index == ZYDIS_REGISTER_NONE && load.operands[1].size == 64)
                    data = true;
                if ((load.instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD ||
                        load.instruction.mnemonic == ZYDIS_MNEMONIC_AND) &&
                    Ordinary(load, load.operands[1]) && load.operands[1].mem.base == wrapper &&
                    load.operands[1].mem.disp.value == 8 && load.operands[1].mem.index == ZYDIS_REGISTER_NONE)
                    flags = true;
                if (expanded && load.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    load.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && load.operands[0].size == 64 &&
                    Ordinary(load, load.operands[1]) && load.operands[1].size == 64 &&
                    load.operands[1].mem.base == wrapper && load.operands[1].mem.disp.value == 8 &&
                    load.operands[1].mem.index == ZYDIS_REGISTER_NONE && k + 1 < ins.size()) {
                    const auto& mask = ins[k + 1];
                    if (mask.instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
                        Reg(mask.operands[0], load.operands[0].reg.value) && mask.operands[0].size == 64 &&
                        k + 3 < ins.size()) {
                        const auto& branch = ins[k + 2];
                        std::uint64_t target{};
                        if ((branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ ||
                                branch.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ) &&
                            ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                                &branch.instruction, &branch.operands[0], branch.address, &target))) {
                            const auto payload = branch.instruction.mnemonic == ZYDIS_MNEMONIC_JZ
                                ? ins.begin() + k + 3
                                : std::lower_bound(ins.begin(), ins.end(), target,
                                      [](const auto& instruction, std::uint64_t at) {
                                          return instruction.address < at;
                                      });
                            if (payload != ins.end() && payload->instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                                payload->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                payload->operands[0].size == 64 && Ordinary(*payload, payload->operands[1]) &&
                                payload->operands[1].size == 64 && payload->operands[1].mem.base == wrapper &&
                                payload->operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                                payload->operands[1].mem.disp.value == 0)
                                flags = true;
                        }
                    }
                }
                if (load.instruction.meta.category == ZYDIS_CATEGORY_COND_BR &&
                    load.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    std::uint64_t target{};
                    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &load.instruction, &load.operands[0], load.address, &target)))
                        continue;
                    auto branch = std::lower_bound(ins.begin(), ins.end(), target,
                        [](const auto& instruction, std::uint64_t at) { return instruction.address < at; });
                    for (unsigned step = 0; branch != ins.end() && step < 8; ++branch, ++step) {
                        if (branch->instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                            Ordinary(*branch, branch->operands[1]) &&
                            branch->operands[1].mem.base == wrapper &&
                            branch->operands[1].mem.disp.value == 0 &&
                            branch->operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                            branch->operands[1].size == 64)
                            data = true;
                        if (expanded &&
                            (branch->instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD ||
                                branch->instruction.mnemonic == ZYDIS_MNEMONIC_AND) &&
                            Ordinary(*branch, branch->operands[1]) &&
                            branch->operands[1].mem.base == wrapper &&
                            branch->operands[1].mem.disp.value == 8 &&
                            branch->operands[1].mem.index == ZYDIS_REGISTER_NONE)
                            flags = true;
                    }
                }
            }
            if (data && flags)
                primary.insert(field);
        }
    }
    if (discovery) {
        discovery->arrays = arrays.size();
        discovery->primary = primary.size();
    }
    if (count_ambiguous || arrays.size() != 1 || primary.size() != 1)
        return std::nullopt;
    if (discovery)
        discovery->rejection = ModuleRejection::signature;
    std::map<std::uint32_t, std::pair<unsigned, std::size_t>> reads;
    for (std::size_t i = expanded ? 0 : collection_begin; i < (expanded ? ins.size() : checksum.instruction);
        ++i) {
        if (expanded && !(*region)[i])
            continue;
        const auto& d = ins[i];
        const auto& o = d.operands[1];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || !Ordinary(d, o) || o.size != 32 ||
            o.mem.index != ZYDIS_REGISTER_NONE || owned(i, o.mem.base) || o.mem.base == ZYDIS_REGISTER_RSP ||
            o.mem.base == ZYDIS_REGISTER_RIP || o.mem.disp.value < 0x20 || o.mem.disp.value >= 0x400)
            continue;
        auto& item = reads[static_cast<std::uint32_t>(o.mem.disp.value)];
        ++item.first;
        item.second = i;
    }
    std::vector<std::pair<std::size_t, std::uint32_t>> repeated;
    for (const auto& [field, value] : reads)
        if (value.first >= 2)
            repeated.emplace_back(value.second, field);
    std::sort(repeated.begin(), repeated.end());
    if (discovery)
        discovery->repeated = repeated.size();
    if (repeated.size() < 2)
        return std::nullopt;
    const auto a = repeated[repeated.size() - 2].second, b = repeated.back().second;
    if (b != a + 4)
        return std::nullopt;
    if (discovery)
        discovery->rejection = ModuleRejection::none;
    return ModuleLayout{checksum.field, *primary.begin(), arrays.begin()->first, arrays.begin()->first + 8, a,
        0, 8, code.begin, checksum.crc, arrays.begin()->second.mask, arrays.begin()->second.width,
        stores.back().field, arrays.begin()->second.shift, arrays.begin()->second.consumer,
        arrays.begin()->second.direct, arrays.begin()->second.store, arrays.begin()->second.slot,
        arrays.begin()->second.direct_width ? arrays.begin()->second.direct_width
                                            : arrays.begin()->second.width,
        arrays.begin()->second.direct_shift ? arrays.begin()->second.direct_shift
                                            : arrays.begin()->second.shift,
        arrays.begin()->second.byte_mask};
}

std::optional<ModuleLayout> AnimationModules(const Emulator::Program& code,
    const std::function<std::optional<std::int32_t>(std::uint64_t)>& read, ModuleDiscovery* discovery,
    std::uint64_t source_end) {
    if (const auto value = ModuleLayoutFor(code, false, read, discovery, source_end))
        return value;
    return ModuleLayoutFor(code, true, read, discovery, source_end);
}

std::uint32_t AppendCrc(std::uint32_t state, std::uint32_t value) noexcept {
    for (unsigned byte = 0; byte < 4; ++byte) {
        state ^= value & 255u;
        value >>= 8;
        for (unsigned bit = 0; bit < 8; ++bit)
            state = (state >> 1) ^ (0xedb88320u & (0u - (state & 1u)));
    }
    return state;
}

std::optional<std::uint32_t> BaseIdentity(std::span<const std::uint32_t> modules) {
    std::uint32_t crc = 0xffffffffu;
    const Entry* accepted{};
    for (const auto signature : modules) {
        crc = AppendCrc(crc, signature);
        if (const auto* candidate = Find((~crc) ^ decode_mask)) {
            if (accepted && candidate->badge != accepted->badge)
                return std::nullopt;
            accepted = candidate;
        }
    }
    if (!accepted)
        return std::nullopt;
    return accepted->id;
}
}
