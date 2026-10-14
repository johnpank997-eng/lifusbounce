#include "sdk/equipment.hpp"
#include "sdk/locator.hpp"
#include <set>

namespace base::sdk::equipment {
static std::optional<OwnershipPath> LegacyDefuserOwner(
    const Emulator::Program& native, const ValidationObserver& validation) {
    const auto reject = [&](std::string_view reason, std::uint64_t at, std::uint64_t observed = 0) {
        if (validation)
            validation(reason, at, observed);
        return std::optional<OwnershipPath>{};
    };
    const auto& ins = native.instructions;
    bool anchor{};
    for (std::size_t i = 0; i + 2 < std::min<std::size_t>(ins.size(), 20); ++i)
        anchor |= ins[i].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            ins[i].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[i].operands[0].reg.value == ZYDIS_REGISTER_ECX &&
            ins[i].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ins[i].operands[1].imm.value.u == 0x1c &&
            ins[i + 1].instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            ins[i + 2].instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
            ins[i + 2].operands[0].reg.value == ZYDIS_REGISTER_AL &&
            ins[i + 2].operands[1].reg.value == ZYDIS_REGISTER_AL;
    if (!anchor)
        return reject("defuser event call and boolean consumer missing", native.begin);
    std::size_t begin = ins.size();
    ZydisRegister input = ZYDIS_REGISTER_NONE;
    for (std::size_t i = 0; i + 1 < ins.size(); ++i)
        if (ins[i].instruction.mnemonic == ZYDIS_MNEMONIC_XOR &&
            ins[i].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && ins[i].operands[0].size == 32 &&
            ins[i].operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[i].operands[0].reg.value == ins[i].operands[1].reg.value &&
            ins[i + 1].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            ins[i + 1].operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[i + 1].operands[1].reg.value == ZYDIS_REGISTER_RSP) {
            if (begin != ins.size())
                return reject("defuser boolean encoder entry ambiguous", ins[i].address);
            begin = i + 1;
            input = ins[i].operands[0].reg.value;
        }
    if (begin == ins.size())
        return reject("defuser boolean encoder entry missing", native.begin);
    OwnershipPath path;
    path.input = input;
    unsigned stores{};
    bool tls{}, rotation{};
    std::size_t end{};
    for (std::size_t i = begin; i < ins.size(); ++i) {
        const auto& d = ins[i];
        if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL ||
            d.instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            d.instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            d.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            break;
        rotation |=
            d.instruction.mnemonic == ZYDIS_MNEMONIC_ROL || d.instruction.mnemonic == ZYDIS_MNEMONIC_ROR;
        for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
            const auto& o = d.operands[j];
            tls |= o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.segment == ZYDIS_REGISTER_GS &&
                o.mem.disp.value == 0x58;
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || o.size != 8 ||
                o.mem.index != ZYDIS_REGISTER_NONE || o.mem.base == ZYDIS_REGISTER_RIP ||
                o.mem.disp.value < 0x40 || o.mem.disp.value >= 0x1000)
                return reject("defuser byte store destination not proven", d.address, o.size);
            if (stores && (path.object != o.mem.base || path.field != o.mem.disp.value))
                return reject("defuser byte store destination ambiguous", d.address);
            path.object = o.mem.base;
            path.field = static_cast<std::uint32_t>(o.mem.disp.value);
            ++stores;
            end = i + 1;
        }
    }

    if ((stores != 1 && stores != 2) || !tls || !rotation || path.object == ZYDIS_REGISTER_NONE)
        return reject(stores != 1 && stores != 2 ? "defuser byte store count rejected"
                : !tls                           ? "defuser tls seed missing"
                : !rotation                      ? "defuser rotation missing"
                                                 : "defuser receiver missing",
            native.begin, stores);

    for (std::size_t i = 0; i < begin; ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            path.encoder.instructions.push_back(d);
    }
    path.encoder.instructions.insert(path.encoder.instructions.end(), ins.begin() + begin, ins.begin() + end);
    path.encoder.begin = path.encoder.instructions.front().address;
    path.encoder.end = ins[end - 1].address + ins[end - 1].instruction.length;
    path.encoder.linear = true;
    return path;
}

namespace {
unsigned DefuserDependency(ZydisRegister reg) {
    const auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
    if (ZydisRegisterGetClass(largest) != ZYDIS_REGCLASS_GPR64)
        return 0;
    return 1u << ZydisRegisterGetId(largest);
}

unsigned DefuserIndex(ZydisRegister reg) {
    return ZydisRegisterGetId(ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg));
}

bool DefuserLowByte(ZydisRegister reg) {
    constexpr std::array values{ZYDIS_REGISTER_AL, ZYDIS_REGISTER_CL, ZYDIS_REGISTER_DL, ZYDIS_REGISTER_BL,
        ZYDIS_REGISTER_SPL, ZYDIS_REGISTER_BPL, ZYDIS_REGISTER_SIL, ZYDIS_REGISTER_DIL, ZYDIS_REGISTER_R8B,
        ZYDIS_REGISTER_R9B, ZYDIS_REGISTER_R10B, ZYDIS_REGISTER_R11B, ZYDIS_REGISTER_R12B,
        ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B};
    return std::find(values.begin(), values.end(), reg) != values.end();
}

struct DefuserSignal {
    unsigned mask = 1;
    std::uint64_t origin{};
    unsigned zero{};
    unsigned value{};
    bool operator==(const DefuserSignal&) const = default;
};

struct DefuserState {
    std::array<DefuserSignal, 16> values;
    unsigned aliases = DefuserDependency(ZYDIS_REGISTER_RCX);
    std::set<std::int64_t> slots;
    bool operator==(const DefuserState&) const = default;
};

DefuserSignal DefuserMerge(DefuserSignal a, DefuserSignal b) {
    if (a == b)
        return a;
    if (a.mask == 2 && !(b.mask & 1) && a.zero == b.zero)
        return {b.mask | 2, b.origin, b.zero, b.value};
    if (b.mask == 2 && !(a.mask & 1) && a.zero == b.zero)
        return {a.mask | 2, a.origin, a.zero, a.value};
    if (!(a.mask & 1) && !(b.mask & 1) && a.origin == b.origin && a.zero == b.zero && a.value == b.value)
        return {a.mask | b.mask, a.origin, a.zero, a.value};
    return {};
}

std::vector<std::optional<DefuserState>> DefuserStates(const Emulator::Program& native) {
    const auto& ins = native.instructions;
    std::vector<std::optional<DefuserState>> states(ins.size());
    if (ins.empty())
        return {};
    states.front() = DefuserState{};
    std::vector<std::size_t> pending{0};
    unsigned steps{};
    while (!pending.empty() && steps++ < 16384) {
        const auto at = pending.back();
        pending.pop_back();
        const auto& d = ins[at];
        const auto before = *states[at];
        auto after = before;
        for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
            const auto& o = d.operands[j];
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != ZYDIS_REGISTER_RSP ||
                o.mem.index != ZYDIS_REGISTER_NONE || !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            for (auto slot = after.slots.begin(); slot != after.slots.end();)
                if (*slot < o.mem.disp.value + o.size / 8 && o.mem.disp.value < *slot + 8)
                    slot = after.slots.erase(slot);
                else
                    ++slot;
            if (j == 0 && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && o.size == 64 &&
                d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[1].size == 64 &&
                (before.aliases & DefuserDependency(d.operands[1].reg.value)))
                after.slots.insert(o.mem.disp.value);
        }
        for (unsigned j = 0; j < d.instruction.operand_count; ++j) {
            const auto& o = d.operands[j];
            if (o.type != ZYDIS_OPERAND_TYPE_REGISTER || !DefuserDependency(o.reg.value) ||
                !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            const auto index = DefuserIndex(o.reg.value), bit = DefuserDependency(o.reg.value);
            DefuserSignal signal{};
            bool alias{};
            if (o.size == 8 && !DefuserLowByte(o.reg.value)) {
                after.aliases &= ~bit;
                continue;
            }
            if (j == 0 && !(o.actions & ZYDIS_OPERAND_ACTION_CONDWRITE)) {
                const auto& value = d.operands[1];
                if ((d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB) &&
                    value.type == ZYDIS_OPERAND_TYPE_REGISTER && value.reg.value == o.reg.value)
                    signal.mask = 2;
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
                    if (value.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !value.imm.is_relative)
                        signal = {2, 0, static_cast<unsigned>(value.imm.value.u & 255),
                            static_cast<unsigned>(value.imm.value.u & 255)};
                    if (value.type == ZYDIS_OPERAND_TYPE_REGISTER && DefuserDependency(value.reg.value) &&
                        (value.size != 8 || DefuserLowByte(value.reg.value))) {
                        signal = before.values[DefuserIndex(value.reg.value)];
                        alias = o.size == 64 && value.size == 64 &&
                            (before.aliases & DefuserDependency(value.reg.value));
                    }
                    alias |= o.size == 64 && value.type == ZYDIS_OPERAND_TYPE_MEMORY && value.size == 64 &&
                        value.mem.base == ZYDIS_REGISTER_RSP && value.mem.index == ZYDIS_REGISTER_NONE &&
                        before.slots.contains(value.mem.disp.value);
                }
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX &&
                    value.type == ZYDIS_OPERAND_TYPE_REGISTER && value.size == 8 &&
                    DefuserDependency(value.reg.value) && DefuserLowByte(value.reg.value))
                    signal = before.values[DefuserIndex(value.reg.value)];
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_SETZ && o.size == 8 &&
                    DefuserLowByte(o.reg.value))
                    signal = {4, d.address, 0, 1};
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_SETNZ && o.size == 8 && at &&
                    DefuserLowByte(o.reg.value)) {
                    const auto& test = ins[at - 1];
                    if (test.instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
                        test.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && test.operands[0].size == 8 &&
                        DefuserLowByte(test.operands[0].reg.value) &&
                        test.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                        test.operands[1].imm.value.u == 1) {
                        signal = before.values[DefuserIndex(test.operands[0].reg.value)];
                        signal.zero &= 1;
                        signal.value &= 1;
                    }
                }
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA && value.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    DefuserDependency(value.mem.base) && value.mem.base == value.mem.index) {
                    signal = before.values[DefuserIndex(value.mem.base)];
                    signal.zero = (signal.zero * (value.mem.scale + 1) + value.mem.disp.value) & 255;
                    signal.value = (signal.value * (value.mem.scale + 1) + value.mem.disp.value) & 255;
                }
                if (value.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !value.imm.is_relative &&
                    (d.instruction.mnemonic == ZYDIS_MNEMONIC_AND ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_OR ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_ADD ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB ||
                        d.instruction.mnemonic == ZYDIS_MNEMONIC_SHL)) {
                    signal = before.values[index];
                    if (!(signal.mask & 1)) {
                        const auto transform = [&](unsigned input) {
                            const auto operand = static_cast<unsigned>(value.imm.value.u);
                            switch (d.instruction.mnemonic) {
                            case ZYDIS_MNEMONIC_AND:
                                return (input & operand) & 255;
                            case ZYDIS_MNEMONIC_OR:
                                return (input | operand) & 255;
                            case ZYDIS_MNEMONIC_XOR:
                                return (input ^ operand) & 255;
                            case ZYDIS_MNEMONIC_ADD:
                                return (input + operand) & 255;
                            case ZYDIS_MNEMONIC_SUB:
                                return (input - operand) & 255;
                            default: {
                                const auto shift = operand & (o.size == 64 ? 63u : 31u);
                                return shift >= o.size ? 0u : (input << shift) & 255;
                            }
                            }
                        };
                        signal.zero = transform(signal.zero);
                        signal.value = transform(signal.value);
                        if (signal.value == signal.zero)
                            signal = {2, 0, signal.zero, signal.zero};
                    }
                }
            }
            after.values[index] = signal;
            after.aliases = alias ? after.aliases | bit : after.aliases & ~bit;
            if (o.reg.value == ZYDIS_REGISTER_RSP)
                after.slots.clear();
        }
        if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL) {
            after.aliases &= ~0xf07u;
            for (auto slot = after.slots.begin(); slot != after.slots.end();)
                if (*slot < 0x20)
                    slot = after.slots.erase(slot);
                else
                    ++slot;
            for (unsigned j = 0; j < 16; ++j)
                if (0xf07u & (1u << j))
                    after.values[j] = {};
        }
        const auto append = [&](std::size_t target) {
            if (target >= ins.size())
                return;
            auto merged = after;
            if (states[target]) {
                merged.aliases &= states[target]->aliases;
                for (auto slot = merged.slots.begin(); slot != merged.slots.end();)
                    if (!states[target]->slots.contains(*slot))
                        slot = merged.slots.erase(slot);
                    else
                        ++slot;
                for (unsigned j = 0; j < 16; ++j)
                    merged.values[j] = DefuserMerge(merged.values[j], states[target]->values[j]);
            }
            if (!states[target] || merged != *states[target]) {
                states[target] = merged;
                pending.push_back(target);
            }
        };
        const auto category = d.instruction.meta.category;
        if (category != ZYDIS_CATEGORY_RET && category != ZYDIS_CATEGORY_UNCOND_BR)
            append(at + 1);
        if ((category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && d.operands[0].imm.is_relative) {
            const auto target = d.address + d.instruction.length + d.operands[0].imm.value.s;
            const auto found = std::lower_bound(ins.begin(), ins.end(), target,
                [](const auto& instruction, auto address) { return instruction.address < address; });
            if (found != ins.end() && found->address == target)
                append(static_cast<std::size_t>(found - ins.begin()));
        }
    }
    return steps < 16384 ? states : std::vector<std::optional<DefuserState>>{};
}
}

std::optional<OwnershipPath> DefuserOwner(
    const Emulator::Program& native, const ValidationObserver& validation) {
    const auto states = DefuserStates(native);
    if (const auto legacy = LegacyDefuserOwner(native, {}); legacy && !states.empty()) {
        bool receiver = true, convergence{}, initialized{};
        for (const auto& d : legacy->encoder.instructions)
            for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                const auto& o = d.operands[j];
                if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.base != legacy->object)
                    continue;
                if (o.mem.index != ZYDIS_REGISTER_NONE || o.mem.disp.value != legacy->field || o.size != 8 ||
                    ((o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) && !initialized))
                    receiver = false;
                initialized |= (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
            }
        for (std::size_t at = 0; at < native.instructions.size(); ++at) {
            const auto& d = native.instructions[at];
            for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                const auto& o = d.operands[j];
                if (d.address >= legacy->encoder.begin && d.address < legacy->encoder.end &&
                    o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.base == legacy->object &&
                    o.mem.disp.value == legacy->field && (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                    (!states[at] || !(states[at]->aliases & DefuserDependency(legacy->object))))
                    receiver = false;
            }
            if (d.address >= legacy->encoder.begin && d.address < legacy->encoder.end && states[at]) {
                const auto& signal = states[at]->values[DefuserIndex(legacy->input)];
                convergence |= signal.mask == 6 && signal.origin && signal.value != signal.zero;
            }
        }
        if (receiver && convergence) {
            if (validation)
                validation("defuser legacy encoder accepted", native.begin, 1);
            return legacy;
        }
    }
    const auto reject = [&](std::string_view reason, std::uint64_t at, std::uint64_t value = 0) {
        if (validation)
            validation(reason, at, value);
        return std::optional<OwnershipPath>{};
    };
    const auto& ins = native.instructions;
    bool event{};
    for (std::size_t i = 0; i + 2 < std::min<std::size_t>(ins.size(), 20); ++i)
        event |= ins[i].instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            ins[i].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[i].operands[0].reg.value == ZYDIS_REGISTER_ECX &&
            ins[i].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !ins[i].operands[1].imm.is_relative &&
            ins[i].operands[1].imm.value.u == 0x1c &&
            ins[i + 1].instruction.mnemonic == ZYDIS_MNEMONIC_CALL &&
            ins[i + 1].operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ins[i + 1].operands[0].imm.is_relative &&
            ins[i + 2].instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
            ins[i + 2].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[i + 2].operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            ins[i + 2].operands[0].reg.value == ZYDIS_REGISTER_AL &&
            ins[i + 2].operands[1].reg.value == ZYDIS_REGISTER_AL;
    if (!event)
        return reject("defuser event call and boolean consumer missing", native.begin);
    if (states.empty())
        return reject("defuser control flow proof limit", native.begin);
    std::optional<OwnershipPath> accepted;
    for (std::size_t condition = 1; condition + 1 < ins.size(); ++condition) {
        const auto& set = ins[condition];
        if (set.instruction.mnemonic != ZYDIS_MNEMONIC_SETZ ||
            set.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || set.operands[0].size != 8 ||
            !DefuserLowByte(set.operands[0].reg.value))
            continue;
        auto comparison = condition;
        while (comparison && condition - comparison < 4 &&
            (ins[comparison - 1].instruction.mnemonic == ZYDIS_MNEMONIC_MOV ||
                ins[comparison - 1].instruction.mnemonic == ZYDIS_MNEMONIC_LEA))
            --comparison;
        if (!comparison || ins[comparison - 1].instruction.mnemonic != ZYDIS_MNEMONIC_CMP ||
            ins[comparison - 1].operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            ins[comparison - 1].operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            ins[comparison - 1].operands[0].size != 64 || ins[comparison - 1].operands[1].size != 64)
            continue;
        const auto begin = condition + 1;
        std::vector<std::size_t> pending{begin};
        std::set<std::size_t> seen;
        std::vector<std::size_t> order;
        std::vector<std::size_t> stores;
        bool joined{}, valid = true;
        ZydisRegister object = ZYDIS_REGISTER_NONE;
        std::uint32_t field{};
        while (!pending.empty() && valid && seen.size() < 512) {
            const auto at = pending.back();
            pending.pop_back();
            if (at >= ins.size() || !seen.insert(at).second) {
                valid = false;
                break;
            }
            order.push_back(at);
            if (states[at])
                for (const auto& signal : states[at]->values)
                    joined |= signal.mask == 6 && signal.origin == set.address && signal.value != signal.zero;
            const auto& d = ins[at];
            const auto category = d.instruction.meta.category;
            if (category == ZYDIS_CATEGORY_RET)
                continue;
            if (category == ZYDIS_CATEGORY_CALL || category == ZYDIS_CATEGORY_COND_BR) {
                valid = false;
                break;
            }
            for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                const auto& o = d.operands[j];
                if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || !(o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                    continue;
                if (o.mem.base == ZYDIS_REGISTER_RSP && o.mem.index == ZYDIS_REGISTER_NONE)
                    continue;
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_OR && o.size == 64 && o.mem.scale == 8 &&
                    o.mem.index != ZYDIS_REGISTER_NONE)
                    continue;
                if ((d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
                        d.instruction.mnemonic != ZYDIS_MNEMONIC_ADD &&
                        d.instruction.mnemonic != ZYDIS_MNEMONIC_SUB &&
                        d.instruction.mnemonic != ZYDIS_MNEMONIC_XOR) ||
                    o.size != 8 || o.mem.index != ZYDIS_REGISTER_NONE || !DefuserDependency(o.mem.base) ||
                    o.mem.disp.value < 0x40 || o.mem.disp.value >= 0x1000 || !states[at] ||
                    !(states[at]->aliases & DefuserDependency(o.mem.base)) ||
                    (object != ZYDIS_REGISTER_NONE && (object != o.mem.base || field != o.mem.disp.value))) {
                    valid = false;
                    break;
                }
                object = o.mem.base;
                field = static_cast<std::uint32_t>(o.mem.disp.value);
                stores.push_back(at);
            }
            if (category == ZYDIS_CATEGORY_UNCOND_BR) {
                if (d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !d.operands[0].imm.is_relative) {
                    valid = false;
                    break;
                }
                const auto target = d.address + d.instruction.length + d.operands[0].imm.value.s;
                const auto found = std::lower_bound(ins.begin(), ins.end(), target,
                    [](const auto& instruction, auto address) { return instruction.address < address; });
                if (found == ins.end() || found->address != target) {
                    valid = false;
                    break;
                }
                pending.push_back(static_cast<std::size_t>(found - ins.begin()));
            } else
                pending.push_back(at + 1);
        }
        if (!valid || !joined || (stores.size() != 1 && stores.size() != 2) ||
            (stores.size() == 2 && stores[0] >= stores[1]))
            continue;
        const auto last = *std::max_element(stores.begin(), stores.end());
        if (last + 2 >= ins.size())
            continue;
        auto normalized = native;
        bool initialized{};
        for (const auto at : order) {
            auto& d = normalized.instructions[at];
            for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                auto& o = d.operands[j];
                if (d.instruction.mnemonic != ZYDIS_MNEMONIC_LEA && o.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    o.mem.base == ZYDIS_REGISTER_RSP &&
                    (o.mem.index != ZYDIS_REGISTER_NONE ||
                        (o.mem.disp.value < 0x5000 && o.mem.disp.value + o.size / 8 > 0x4000))) {
                    valid = false;
                    break;
                }
                if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || !DefuserDependency(o.mem.base) || !states[at] ||
                    !(states[at]->aliases & DefuserDependency(o.mem.base)))
                    continue;
                if (o.mem.index != ZYDIS_REGISTER_NONE || o.mem.disp.value != field || o.size != 8 ||
                    ((o.actions & ZYDIS_OPERAND_ACTION_MASK_READ) && !initialized)) {
                    valid = false;
                    break;
                }
                o.mem.base = ZYDIS_REGISTER_RSP;
                o.mem.segment = ZYDIS_REGISTER_SS;
                o.mem.disp.value += 0x4000;
                initialized |= (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
            }
        }
        if (!valid)
            continue;
        auto& load = normalized.instructions[last + 1];
        std::array<std::byte, 8> bytes{std::byte{0x0f}, std::byte{0xb6}, std::byte{0x84}, std::byte{0x24}};
        const auto displacement = 0x4000u + field;
        for (unsigned j = 0; j < 4; ++j)
            bytes[4 + j] = static_cast<std::byte>((displacement >> (j * 8)) & 0xff);
        const auto decoded = Emulator::Decode(bytes, load.address);
        if (!decoded || decoded->instructions.size() != 1)
            continue;
        const auto stride = load.instruction.length;
        load = decoded->instructions.front();
        load.instruction.length = stride;
        const auto flow = locators::Flow(normalized, begin, last + 2,
            locators::Location{set.operands[0].reg.value, 0, false},
            locators::Location{ZYDIS_REGISTER_EAX, 0, false});
        if (!flow) {
            if (validation)
                validation("defuser native flow rejected", set.address, 0);
            continue;
        }
        std::vector<OwnershipSeed> seeds;
        for (const auto& seed : flow->seeds) {
            if (seed.value.inputs || !DefuserDependency(seed.value.output) ||
                seed.value.output == ZYDIS_REGISTER_RSP ||
                (!seed.target.stack &&
                    (!DefuserDependency(seed.target.reg) || seed.target.reg == ZYDIS_REGISTER_RSP)) ||
                (seed.target.stack &&
                    (seed.target.slot < 0 || seed.target.slot >= 0x4000 || (seed.target.slot & 7)))) {
                valid = false;
                break;
            }
            for (const auto& d : seed.value.code.instructions)
                for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                    const auto& o = d.operands[j];
                    if (o.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                        (o.mem.base != ZYDIS_REGISTER_RSP || o.mem.index != ZYDIS_REGISTER_NONE))
                        valid = false;
                }
            seeds.push_back(
                {seed.value.code, seed.value.output, seed.target.reg, seed.target.slot, seed.target.stack});
        }
        if (!valid) {
            if (validation)
                validation("defuser native seed input rejected", set.address, flow->seeds.size());
            continue;
        }
        bool external{};
        for (const auto& d : flow->code.instructions)
            for (unsigned j = 0; j < d.instruction.operand_count_visible; ++j) {
                const auto& o = d.operands[j];
                external |= o.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (o.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) && o.mem.base != ZYDIS_REGISTER_RSP;
            }
        if (external)
            continue;
        if (accepted)
            return reject("defuser boolean encoder ambiguous", set.address);
        accepted = OwnershipPath{flow->code, object, set.operands[0].reg.value, field, std::move(seeds)};
    }
    if (validation)
        validation(accepted ? "defuser native convergence encoder accepted"
                            : "defuser boolean receiver or encoding proof missing",
            native.begin, accepted ? 1 : 0);
    return accepted;
}
}
