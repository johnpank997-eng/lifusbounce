#include "sdk/operator_native.hpp"
#include <bit>
#include <map>

namespace base::sdk::operators {
std::vector<std::uint16_t> ReceiverBindings(const Emulator::Program& method, std::size_t begin,
    std::size_t complete, const std::function<std::optional<std::int32_t>(std::uint64_t)>& read,
    std::uint64_t source_end, std::vector<std::vector<std::size_t>>* edges,
    std::vector<std::array<std::optional<std::uint64_t>, 16>>* values,
    std::vector<std::map<std::int64_t, std::uint64_t>>* locals, std::vector<StackProvenance>* provenance) {
    struct State {
        std::uint16_t registers{};
        std::set<std::int64_t> slots;
        bool stack = true;
        bool complete{};
        std::uint16_t narrow{};
        std::array<std::optional<std::uint32_t>, 16> limits{};
        std::uint16_t zero{};
        std::array<std::uint16_t, 16> copies{};
        std::optional<std::size_t> flags;
        std::array<std::optional<std::uint64_t>, 16> values{};
        std::map<std::uint64_t, std::uint64_t> globals;
        std::map<std::int64_t, std::uint64_t> locals;
        std::array<std::optional<std::size_t>, 16> writers{};
        std::array<std::optional<std::int64_t>, 16> frames{};
        bool escaped{};
        StackProvenance provenance;
        bool operator==(const State&) const = default;
    };

    const auto bit = [](ZydisRegister reg) -> std::uint16_t {
        const auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
        return largest >= ZYDIS_REGISTER_RAX && largest <= ZYDIS_REGISTER_R15
            ? static_cast<std::uint16_t>(1u << (largest - ZYDIS_REGISTER_RAX))
            : 0;
    };
    const auto& ins = method.instructions;
    if (!source_end)
        source_end = method.end;
    if (begin >= ins.size() || complete >= ins.size() || ins.size() > 16384 || source_end <= method.begin ||
        source_end - method.begin > 0x10000)
        return {};
    std::vector<std::optional<State>> incoming(ins.size());
    if (edges)
        edges->assign(ins.size(), {});
    State entry;
    entry.registers = bit(ZYDIS_REGISTER_RCX);
    for (unsigned r = 0; r < entry.copies.size(); ++r)
        entry.copies[r] = static_cast<std::uint16_t>(1u << r);
    incoming[begin] = entry;
    std::vector<std::size_t> pending{begin};
    std::size_t steps{};
    while (!pending.empty() && ++steps <= ins.size() * 64) {
        const auto i = pending.back();
        pending.pop_back();
        auto state = *incoming[i];
        const auto before = state;
        const auto& d = ins[i];
        const auto category = d.instruction.meta.category;
        if (d.instruction.cpu_flags &&
            (d.instruction.cpu_flags->modified | d.instruction.cpu_flags->set_0 |
                d.instruction.cpu_flags->set_1 | d.instruction.cpu_flags->undefined))
            state.flags = i;
        if (i == complete)
            state.complete = true;
        bool inaccessible{};
        for (unsigned n = 0; n < d.instruction.operand_count; ++n) {
            const auto& operand = d.operands[n];
            const bool access = operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operand.mem.type == ZYDIS_MEMOP_TYPE_MEM && category != ZYDIS_CATEGORY_PREFETCH &&
                category != ZYDIS_CATEGORY_PREFETCHWT1 && operand.mem.segment != ZYDIS_REGISTER_GS &&
                operand.mem.segment != ZYDIS_REGISTER_FS &&
                (operand.actions & (ZYDIS_OPERAND_ACTION_MASK_READ | ZYDIS_OPERAND_ACTION_MASK_WRITE)) &&
                operand.mem.index == ZYDIS_REGISTER_NONE;
            inaccessible |= access && operand.mem.disp.value >= 0 && operand.mem.disp.value < 0x10000 &&
                (state.zero & bit(operand.mem.base));
            const auto mask = bit(operand.mem.base);
            if (access && mask && state.values[std::countr_zero(mask)]) {
                const auto address = *state.values[std::countr_zero(mask)] + operand.mem.disp.value;
                inaccessible |= address < 0x10000 || address >= 0x800000000000ull;
            }
        }
        if (inaccessible)
            continue;
        for (unsigned n = 0; n < d.instruction.operand_count; ++n) {
            const auto& operand = d.operands[n];
            if (!(operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (category != ZYDIS_CATEGORY_CALL && bit(operand.reg.value) == bit(ZYDIS_REGISTER_RSP)) {
                    state.stack = false;
                    state.slots.clear();
                    state.locals.clear();
                    state.provenance.assignments.clear();
                }
                state.registers &= ~bit(operand.reg.value);
                if (const auto mask = bit(operand.reg.value)) {
                    state.zero &= ~mask;
                    for (auto& group : state.copies)
                        group &= ~mask;
                    state.copies[std::countr_zero(mask)] = mask;
                    state.narrow &= ~mask;
                    state.limits[std::countr_zero(mask)].reset();
                    state.values[std::countr_zero(mask)].reset();
                    state.writers[std::countr_zero(mask)] = i;
                    state.frames[std::countr_zero(mask)].reset();
                    state.provenance.sources[std::countr_zero(mask)].reset();
                    if (operand.size == 32)
                        state.narrow |= mask;
                }
            } else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RSP) {
                if (operand.mem.index != ZYDIS_REGISTER_NONE || !operand.size) {
                    state.slots.clear();
                    state.locals.clear();
                    state.provenance.assignments.clear();
                    continue;
                }
                const auto start = operand.mem.disp.value;
                const auto length = operand.size / 8;
                for (auto it = state.slots.begin(); it != state.slots.end();)
                    if (*it < start + length && start < *it + 8)
                        it = state.slots.erase(it);
                    else
                        ++it;
                for (auto it = state.locals.begin(); it != state.locals.end();)
                    if (it->first < start + length && start < it->first + 8)
                        it = state.locals.erase(it);
                    else
                        ++it;
                for (auto it = state.provenance.assignments.begin();
                    it != state.provenance.assignments.end();)
                    if (it->first < start + length && start < it->first + 8)
                        it = state.provenance.assignments.erase(it);
                    else
                        ++it;
            } else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                std::uint64_t at{};
                if (operand.mem.base == ZYDIS_REGISTER_RIP && operand.mem.index == ZYDIS_REGISTER_NONE &&
                    operand.mem.segment != ZYDIS_REGISTER_FS && operand.mem.segment != ZYDIS_REGISTER_GS &&
                    operand.size &&
                    ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &operand, d.address, &at))) {
                    for (auto it = state.globals.begin(); it != state.globals.end();)
                        if (it->first < at + operand.size / 8 && at < it->first + 8)
                            it = state.globals.erase(it);
                        else
                            ++it;
                } else {
                    state.globals.clear();
                    state.locals.clear();
                }
            }
        }
        const auto& a = d.operands[0];
        const auto& b = d.operands[1];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && a.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            a.size == 64 && b.size == 64) {
            const bool alias = b.type == ZYDIS_OPERAND_TYPE_REGISTER
                ? (before.registers & bit(b.reg.value)) != 0
                : b.type == ZYDIS_OPERAND_TYPE_MEMORY && b.mem.base == ZYDIS_REGISTER_RSP &&
                    b.mem.index == ZYDIS_REGISTER_NONE && d.instruction.address_width == 64 &&
                    b.mem.segment != ZYDIS_REGISTER_FS && b.mem.segment != ZYDIS_REGISTER_GS &&
                    before.stack && before.slots.contains(b.mem.disp.value);
            if (alias)
                state.registers |= bit(a.reg.value);
            if (b.type == ZYDIS_OPERAND_TYPE_REGISTER && bit(b.reg.value) && bit(a.reg.value)) {
                const auto group = static_cast<std::uint16_t>(
                    before.copies[std::countr_zero(bit(b.reg.value))] | bit(a.reg.value));
                for (unsigned r = 0; r < state.copies.size(); ++r)
                    if (group & (1u << r))
                        state.copies[r] = group;
                if (before.zero & bit(b.reg.value))
                    state.zero |= bit(a.reg.value);
                state.values[std::countr_zero(bit(a.reg.value))] =
                    before.values[std::countr_zero(bit(b.reg.value))];
                state.frames[std::countr_zero(bit(a.reg.value))] = b.reg.value == ZYDIS_REGISTER_RSP
                    ? std::optional<std::int64_t>(0)
                    : before.frames[std::countr_zero(bit(b.reg.value))];
                state.provenance.sources[std::countr_zero(bit(a.reg.value))] =
                    before.provenance.sources[std::countr_zero(bit(b.reg.value))];
            }
            if (b.type == ZYDIS_OPERAND_TYPE_REGISTER && bit(b.reg.value) &&
                (before.narrow & bit(b.reg.value))) {
                state.narrow |= bit(a.reg.value);
                state.limits[std::countr_zero(bit(a.reg.value))] =
                    before.limits[std::countr_zero(bit(b.reg.value))];
            }
        }
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && d.instruction.address_width == 64 &&
            a.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size == 64 && bit(a.reg.value) &&
            b.type == ZYDIS_OPERAND_TYPE_MEMORY && b.size == 64 && b.mem.base == ZYDIS_REGISTER_RSP &&
            b.mem.index == ZYDIS_REGISTER_NONE && b.mem.segment != ZYDIS_REGISTER_FS &&
            b.mem.segment != ZYDIS_REGISTER_GS && before.stack)
            state.provenance.sources[std::countr_zero(bit(a.reg.value))] = b.mem.disp.value;
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA && d.instruction.address_width == 64 &&
            a.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size == 64 && bit(a.reg.value) &&
            b.type == ZYDIS_OPERAND_TYPE_MEMORY && b.mem.index == ZYDIS_REGISTER_NONE && before.stack) {
            const auto origin = b.mem.base == ZYDIS_REGISTER_RSP ? std::optional<std::int64_t>(0)
                : bit(b.mem.base) ? before.frames[std::countr_zero(bit(b.mem.base))]
                                  : std::nullopt;
            if (origin && b.mem.disp.value > -0x10000 && b.mem.disp.value < 0x10000 &&
                *origin + b.mem.disp.value > -0x10000 && *origin + b.mem.disp.value < 0x10000)
                state.frames[std::countr_zero(bit(a.reg.value))] = *origin + b.mem.disp.value;
        }
        if (a.type == ZYDIS_OPERAND_TYPE_MEMORY && a.mem.base != ZYDIS_REGISTER_RSP &&
            (a.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) && b.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            bit(b.reg.value) && before.frames[std::countr_zero(bit(b.reg.value))]) {
            state.escaped = true;
            state.locals.clear();
        }
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && a.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            bit(a.reg.value) && (a.size == 32 || a.size == 64)) {
            if (b.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                state.values[std::countr_zero(bit(a.reg.value))] =
                    a.size == 32 ? std::uint32_t(b.imm.value.u) : b.imm.value.u;
            else if (a.size == 64 && b.type == ZYDIS_OPERAND_TYPE_MEMORY && b.size == 64 &&
                b.mem.base == ZYDIS_REGISTER_RIP && b.mem.index == ZYDIS_REGISTER_NONE &&
                b.mem.segment != ZYDIS_REGISTER_FS && b.mem.segment != ZYDIS_REGISTER_GS) {
                std::uint64_t at{};
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &b, d.address, &at)))
                    if (const auto found = before.globals.find(at); found != before.globals.end())
                        state.values[std::countr_zero(bit(a.reg.value))] = found->second;
            } else if (a.size == 64 && b.type == ZYDIS_OPERAND_TYPE_MEMORY && b.size == 64 &&
                b.mem.base == ZYDIS_REGISTER_RSP && b.mem.index == ZYDIS_REGISTER_NONE &&
                d.instruction.address_width == 64 && b.mem.segment != ZYDIS_REGISTER_FS &&
                b.mem.segment != ZYDIS_REGISTER_GS && before.stack) {
                if (const auto found = before.locals.find(b.mem.disp.value); found != before.locals.end())
                    state.values[std::countr_zero(bit(a.reg.value))] = found->second;
            } else if (a.size == 32 && b.type == ZYDIS_OPERAND_TYPE_REGISTER && bit(b.reg.value) &&
                before.values[std::countr_zero(bit(b.reg.value))])
                state.values[std::countr_zero(bit(a.reg.value))] =
                    std::uint32_t(*before.values[std::countr_zero(bit(b.reg.value))]);
        }
        if (a.type == ZYDIS_OPERAND_TYPE_REGISTER && bit(a.reg.value) && (a.size == 32 || a.size == 64)) {
            const auto width = a.size == 32 ? 0xffffffffull : ~0ull;
            const auto x = before.values[std::countr_zero(bit(a.reg.value))];
            const auto y = b.type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                ? std::optional<std::uint64_t>(b.imm.value.u)
                : b.type == ZYDIS_OPERAND_TYPE_REGISTER && bit(b.reg.value)
                ? before.values[std::countr_zero(bit(b.reg.value))]
                : std::nullopt;
            auto& value = state.values[std::countr_zero(bit(a.reg.value))];
            if (x && y)
                switch (d.instruction.mnemonic) {
                case ZYDIS_MNEMONIC_ADD:
                    value = (*x + *y) & width;
                    break;
                case ZYDIS_MNEMONIC_SUB:
                    value = (*x - *y) & width;
                    break;
                case ZYDIS_MNEMONIC_XOR:
                    value = (*x ^ *y) & width;
                    break;
                case ZYDIS_MNEMONIC_OR:
                    value = (*x | *y) & width;
                    break;
                case ZYDIS_MNEMONIC_AND:
                    value = (*x & *y) & width;
                    break;
                case ZYDIS_MNEMONIC_SHL:
                    value = (*x << (*y & (a.size - 1))) & width;
                    break;
                case ZYDIS_MNEMONIC_SHR:
                    value = (*x & width) >> (*y & (a.size - 1));
                    break;
                default:
                    break;
                }
            if (x && d.instruction.mnemonic == ZYDIS_MNEMONIC_NOT)
                value = ~*x & width;
            if (x && d.instruction.mnemonic == ZYDIS_MNEMONIC_NEG)
                value = (0ull - *x) & width;
            if (d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA && b.type == ZYDIS_OPERAND_TYPE_MEMORY) {
                const auto base = b.mem.base == ZYDIS_REGISTER_NONE ? std::optional<std::uint64_t>(0)
                    : b.mem.base == ZYDIS_REGISTER_RIP
                    ? std::optional<std::uint64_t>(d.address + d.instruction.length)
                    : bit(b.mem.base) ? before.values[std::countr_zero(bit(b.mem.base))]
                                      : std::nullopt;
                const auto index = b.mem.index == ZYDIS_REGISTER_NONE ? std::optional<std::uint64_t>(0)
                    : bit(b.mem.index) ? before.values[std::countr_zero(bit(b.mem.index))]
                                       : std::nullopt;
                if (base && index)
                    value = (*base + *index * b.mem.scale + b.mem.disp.value) & width &
                        (d.instruction.address_width == 32 ? 0xffffffffull : ~0ull);
            }
            if (value && !*value)
                state.zero |= bit(a.reg.value);
        }
        if ((d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV || d.instruction.mnemonic == ZYDIS_MNEMONIC_XCHG) &&
            a.type == ZYDIS_OPERAND_TYPE_MEMORY && a.size == 64 && a.mem.base == ZYDIS_REGISTER_RIP &&
            a.mem.index == ZYDIS_REGISTER_NONE && a.mem.segment != ZYDIS_REGISTER_FS &&
            a.mem.segment != ZYDIS_REGISTER_GS && b.type == ZYDIS_OPERAND_TYPE_REGISTER && b.size == 64 &&
            bit(b.reg.value) && before.values[std::countr_zero(bit(b.reg.value))]) {
            std::uint64_t at{};
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &a, d.address, &at))) {
                if (state.globals.size() >= 64 && !state.globals.contains(at))
                    return {};
                state.globals[at] = *before.values[std::countr_zero(bit(b.reg.value))];
            }
        }
        if ((d.instruction.mnemonic == ZYDIS_MNEMONIC_XOR || d.instruction.mnemonic == ZYDIS_MNEMONIC_SUB) &&
            a.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size >= 32 && b.type == ZYDIS_OPERAND_TYPE_REGISTER &&
            b.reg.value == a.reg.value) {
            state.zero |= bit(a.reg.value);
            state.values[std::countr_zero(bit(a.reg.value))] = 0;
        }
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && d.instruction.address_width == 64 &&
            a.type == ZYDIS_OPERAND_TYPE_MEMORY && a.mem.segment != ZYDIS_REGISTER_FS &&
            a.mem.segment != ZYDIS_REGISTER_GS && a.size == 64 && a.mem.base == ZYDIS_REGISTER_RSP &&
            a.mem.index == ZYDIS_REGISTER_NONE && state.stack && b.size == 64) {
            if (b.type == ZYDIS_OPERAND_TYPE_REGISTER && (before.registers & bit(b.reg.value))) {
                if (state.slots.size() >= 64)
                    return {};
                state.slots.insert(a.mem.disp.value);
            }
            const auto constant = b.type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                ? std::optional<std::uint64_t>(b.imm.value.u)
                : b.type == ZYDIS_OPERAND_TYPE_REGISTER && bit(b.reg.value)
                ? before.values[std::countr_zero(bit(b.reg.value))]
                : std::nullopt;
            if (constant) {
                if (state.locals.size() >= 64 && !state.locals.contains(a.mem.disp.value))
                    return {};
                state.locals[a.mem.disp.value] = *constant;
                if (state.provenance.assignments.size() >= 64 &&
                    !state.provenance.assignments.contains(a.mem.disp.value))
                    return {};
                state.provenance.assignments[a.mem.disp.value] = {*constant, d.address};
            }
        }
        if (category == ZYDIS_CATEGORY_CALL) {
            state.flags.reset();
            state.globals.clear();
            bool frame = state.escaped;
            for (const auto reg :
                {ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9})
                frame |= before.frames[std::countr_zero(bit(reg))].has_value();
            if (frame)
                state.locals.clear();
            for (auto it = state.slots.begin(); it != state.slots.end();)
                if (*it < 0x20)
                    it = state.slots.erase(it);
                else
                    ++it;
            for (auto it = state.locals.begin(); it != state.locals.end();)
                if (it->first < 0x20)
                    it = state.locals.erase(it);
                else
                    ++it;
            for (auto it = state.provenance.assignments.begin(); it != state.provenance.assignments.end();)
                if (it->first < 0x20)
                    it = state.provenance.assignments.erase(it);
                else
                    ++it;
            for (const auto reg : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
                     ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11}) {
                state.registers &= ~bit(reg);
                state.narrow &= ~bit(reg);
                state.limits[std::countr_zero(bit(reg))].reset();
                state.values[std::countr_zero(bit(reg))].reset();
                state.writers[std::countr_zero(bit(reg))].reset();
                state.frames[std::countr_zero(bit(reg))].reset();
                state.provenance.sources[std::countr_zero(bit(reg))].reset();
                state.zero &= ~bit(reg);
                for (auto& group : state.copies)
                    group &= ~bit(reg);
                state.copies[std::countr_zero(bit(reg))] = bit(reg);
            }
        }
        const auto propagate = [&](std::size_t target, const State& outgoing) {
            if (target >= ins.size())
                return;
            if (edges && std::find((*edges)[i].begin(), (*edges)[i].end(), target) == (*edges)[i].end())
                (*edges)[i].push_back(target);
            if (!incoming[target]) {
                incoming[target] = outgoing;
                pending.push_back(target);
                return;
            }
            auto merged = *incoming[target];
            merged.registers &= outgoing.registers;
            merged.stack &= outgoing.stack;
            merged.complete &= outgoing.complete;
            merged.narrow &= outgoing.narrow;
            merged.zero &= outgoing.zero;
            merged.escaped |= outgoing.escaped;
            for (unsigned r = 0; r < merged.copies.size(); ++r)
                merged.copies[r] &= outgoing.copies[r];
            for (unsigned r = 0; r < merged.values.size(); ++r) {
                if (merged.values[r] != outgoing.values[r])
                    merged.values[r].reset();
                if (merged.writers[r] != outgoing.writers[r])
                    merged.writers[r].reset();
                if (merged.frames[r] != outgoing.frames[r])
                    merged.frames[r].reset();
                if (merged.provenance.sources[r] != outgoing.provenance.sources[r])
                    merged.provenance.sources[r].reset();
            }
            for (auto it = merged.globals.begin(); it != merged.globals.end();)
                if (!outgoing.globals.contains(it->first) || outgoing.globals.at(it->first) != it->second)
                    it = merged.globals.erase(it);
                else
                    ++it;
            for (auto it = merged.locals.begin(); it != merged.locals.end();)
                if (!outgoing.locals.contains(it->first) || outgoing.locals.at(it->first) != it->second)
                    it = merged.locals.erase(it);
                else
                    ++it;
            for (auto it = merged.provenance.assignments.begin(); it != merged.provenance.assignments.end();)
                if (!outgoing.provenance.assignments.contains(it->first) ||
                    outgoing.provenance.assignments.at(it->first) != it->second)
                    it = merged.provenance.assignments.erase(it);
                else
                    ++it;
            if (merged.flags != outgoing.flags)
                merged.flags.reset();
            for (unsigned r = 0; r < merged.limits.size(); ++r)
                if (merged.limits[r] && outgoing.limits[r])
                    merged.limits[r] = std::max(*merged.limits[r], *outgoing.limits[r]);
                else
                    merged.limits[r].reset();
            for (auto it = merged.slots.begin(); it != merged.slots.end();)
                if (!outgoing.slots.contains(*it))
                    it = merged.slots.erase(it);
                else
                    ++it;
            if (merged != *incoming[target]) {
                incoming[target] = std::move(merged);
                pending.push_back(target);
            }
        };
        if (category == ZYDIS_CATEGORY_RET)
            continue;
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            std::uint64_t target{};
            if (d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &d.operands[0], d.address, &target))) {
                if (read && category == ZYDIS_CATEGORY_UNCOND_BR && i >= 3 &&
                    d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    const auto& add = ins[i - 1];
                    const auto& load = ins[i - 2];
                    const auto& base = ins[i - 3];
                    const auto index = load.operands[1].mem.index;
                    const auto register_index = bit(index) ? std::countr_zero(bit(index)) : 16;
                    const auto jump_register =
                        bit(d.operands[0].reg.value) ? std::countr_zero(bit(d.operands[0].reg.value)) : 16;
                    const auto base_register = bit(base.operands[0].reg.value)
                        ? std::countr_zero(bit(base.operands[0].reg.value))
                        : 16;
                    const auto& limit = register_index < 16 && incoming[i - 2]
                        ? incoming[i - 2]->limits[register_index]
                        : std::optional<std::uint32_t>{};
                    std::uint64_t table{};
                    if (base.instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                        base.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && base.operands[0].size == 64 &&
                        base.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                        base.operands[1].mem.base == ZYDIS_REGISTER_RIP &&
                        load.instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD &&
                        load.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && load.operands[0].size == 64 &&
                        load.operands[0].reg.value == d.operands[0].reg.value &&
                        load.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && load.operands[1].size == 32 &&
                        load.operands[1].mem.segment != ZYDIS_REGISTER_FS &&
                        load.operands[1].mem.segment != ZYDIS_REGISTER_GS &&
                        load.operands[1].mem.base == base.operands[0].reg.value &&
                        load.operands[1].mem.scale == 4 && load.operands[1].mem.disp.value == 0 &&
                        add.instruction.mnemonic == ZYDIS_MNEMONIC_ADD &&
                        add.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && add.operands[0].size == 64 &&
                        add.operands[1].size == 64 && d.operands[0].size == 64 &&
                        add.operands[0].reg.value == load.operands[0].reg.value &&
                        add.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                        add.operands[1].reg.value == base.operands[0].reg.value && jump_register < 16 &&
                        base_register < 16 && before.writers[jump_register] == i - 1 && incoming[i - 1] &&
                        incoming[i - 1]->writers[jump_register] == i - 2 && incoming[i - 2] &&
                        incoming[i - 2]->writers[base_register] == i - 3 && limit && *limit <= 63 &&
                        incoming[i - 2] && (incoming[i - 2]->narrow & bit(index)) &&
                        ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &base.instruction, &base.operands[1], base.address, &table)) &&
                        table >= method.begin && table <= source_end &&
                        std::uint64_t(*limit + 1) * 4 <= source_end - table) {
                        std::vector<std::size_t> targets;
                        for (std::uint32_t n = 0; n <= *limit; ++n) {
                            const auto offset = read(table + n * 4);
                            if (!offset)
                                return {};
                            const auto at = std::lower_bound(ins.begin(), ins.end(), table + *offset,
                                [](const auto& instruction, std::uint64_t value) {
                                    return instruction.address < value;
                                });
                            if (at == ins.end() || at->address != table + *offset)
                                return {};
                            targets.push_back(at - ins.begin());
                        }
                        for (const auto at : targets)
                            propagate(at, state);
                        continue;
                    }
                }
                if (state.complete)
                    continue;
                return {};
            }
            const auto found = std::lower_bound(ins.begin(), ins.end(), target,
                [](const auto& instruction, std::uint64_t at) { return instruction.address < at; });
            if (found == ins.end() || found->address != target) {
                if (state.complete)
                    continue;
                return {};
            }
            auto branch = state, next = state;
            if (i && state.flags == i - 1 && ins[i - 1].instruction.mnemonic == ZYDIS_MNEMONIC_TEST &&
                ins[i - 1].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ins[i - 1].operands[0].size == 64 &&
                ins[i - 1].operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ins[i - 1].operands[1].reg.value == ins[i - 1].operands[0].reg.value &&
                bit(ins[i - 1].operands[0].reg.value)) {
                const auto r = std::countr_zero(bit(ins[i - 1].operands[0].reg.value));
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_JZ)
                    branch.zero |= state.copies[r];
                else if (d.instruction.mnemonic == ZYDIS_MNEMONIC_JNZ)
                    next.zero |= state.copies[r];
            }
            if (i && state.flags == i - 1 && ins[i - 1].instruction.mnemonic == ZYDIS_MNEMONIC_CMP &&
                ins[i - 1].operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                ins[i - 1].operands[0].size == 32 && bit(ins[i - 1].operands[0].reg.value) &&
                ins[i - 1].operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ins[i - 1].operands[1].imm.value.u <= 63 &&
                (state.narrow & bit(ins[i - 1].operands[0].reg.value))) {
                const auto r = std::countr_zero(bit(ins[i - 1].operands[0].reg.value));
                const auto maximum = static_cast<std::uint32_t>(ins[i - 1].operands[1].imm.value.u);
                if (d.instruction.mnemonic == ZYDIS_MNEMONIC_JNBE)
                    next.limits[r] = maximum;
                else if (d.instruction.mnemonic == ZYDIS_MNEMONIC_JBE)
                    branch.limits[r] = maximum;
            }
            propagate(found - ins.begin(), branch);
            if (category == ZYDIS_CATEGORY_UNCOND_BR)
                continue;
            propagate(i + 1, next);
            continue;
        }
        propagate(i + 1, state);
    }
    if (steps > ins.size() * 64)
        return {};
    std::vector<std::uint16_t> result(ins.size());
    if (values)
        values->assign(ins.size(), {});
    if (locals)
        locals->assign(ins.size(), {});
    if (provenance)
        provenance->assign(ins.size(), {});
    for (std::size_t i = 0; i < incoming.size(); ++i)
        if (incoming[i]) {
            result[i] = incoming[i]->registers;
            if (values)
                (*values)[i] = incoming[i]->values;
            if (locals)
                (*locals)[i] = incoming[i]->locals;
            if (provenance)
                (*provenance)[i] = incoming[i]->provenance;
        }
    return result;
}

std::vector<SharedMember> SharedMembers(const Emulator::Program& method) {
    using Aliases = std::array<std::optional<std::int64_t>, 16>;
    const auto index = [](ZydisRegister reg) -> std::optional<unsigned> {
        const auto largest = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
        if (largest < ZYDIS_REGISTER_RAX || largest > ZYDIS_REGISTER_R15)
            return std::nullopt;
        return static_cast<unsigned>(largest - ZYDIS_REGISTER_RAX);
    };
    const auto& ins = method.instructions;
    if (ins.empty() || ins.size() > 4096)
        return {};
    std::vector<std::optional<Aliases>> incoming(ins.size());
    Aliases entry{};
    entry[*index(ZYDIS_REGISTER_RCX)] = 0;
    incoming[0] = entry;
    std::vector<std::size_t> pending{0};
    unsigned steps{};
    while (!pending.empty() && ++steps <= ins.size() * 64) {
        const auto i = pending.back();
        pending.pop_back();
        auto state = *incoming[i];
        const auto& d = ins[i];
        const auto before = state;
        for (unsigned n = 0; n < d.instruction.operand_count; ++n) {
            const auto& operand = d.operands[n];
            if (operand.type != ZYDIS_OPERAND_TYPE_REGISTER ||
                !(operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                continue;
            if (const auto k = index(operand.reg.value))
                state[*k].reset();
        }
        const auto& a = d.operands[0];
        const auto& b = d.operands[1];
        if (a.type == ZYDIS_OPERAND_TYPE_REGISTER && a.size == 64) {
            const auto to = index(a.reg.value);
            if (to && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && b.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                if (const auto from = index(b.reg.value))
                    state[*to] = before[*from];
            } else if (to && d.instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
                b.type == ZYDIS_OPERAND_TYPE_MEMORY && b.mem.index == ZYDIS_REGISTER_NONE) {
                const auto from = index(b.mem.base);
                if (from && before[*from] && b.mem.disp.value > -0x10000 && b.mem.disp.value < 0x10000)
                    state[*to] = *before[*from] + b.mem.disp.value;
            }
        }
        if (d.instruction.meta.category == ZYDIS_CATEGORY_CALL)
            for (const auto reg : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
                     ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11})
                state[*index(reg)].reset();
        const auto propagate = [&](std::size_t target) {
            if (target >= ins.size())
                return;
            if (!incoming[target]) {
                incoming[target] = state;
                pending.push_back(target);
                return;
            }
            auto merged = *incoming[target];
            for (unsigned k = 0; k < merged.size(); ++k)
                if (merged[k] != state[k])
                    merged[k].reset();
            if (merged != *incoming[target]) {
                incoming[target] = merged;
                pending.push_back(target);
            }
        };
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            continue;
        const auto category = d.instruction.meta.category;
        if (category == ZYDIS_CATEGORY_COND_BR || category == ZYDIS_CATEGORY_UNCOND_BR) {
            std::uint64_t target{};
            if (d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &d.operands[0], d.address, &target)))
                return {};
            const auto found = std::lower_bound(ins.begin(), ins.end(), target,
                [](const auto& at, std::uint64_t value) { return at.address < value; });
            if (found == ins.end() || found->address != target)
                return {};
            propagate(found - ins.begin());
            if (category == ZYDIS_CATEGORY_UNCOND_BR)
                continue;
        }
        propagate(i + 1);
    }
    if (steps > ins.size() * 64)
        return {};
    std::vector<SharedMember> result;
    for (std::size_t i = 0; i < ins.size(); ++i) {
        const auto& d = ins[i];
        if (!incoming[i] || d.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
            continue;
        const auto field = (*incoming[i])[*index(ZYDIS_REGISTER_RDX)];
        if (!field || *field < 8 || *field > 0x10000 || (*incoming[i])[*index(ZYDIS_REGISTER_RCX)])
            continue;
        std::uint64_t copy{};
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&d.instruction, &d.operands[0], d.address, &copy)))
            continue;
        const SharedMember member{static_cast<std::uint32_t>(*field), method.begin, copy};
        if (std::find(result.begin(), result.end(), member) == result.end())
            result.push_back(member);
    }
    return result;
}
}
