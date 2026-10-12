#include "sdk/operator_native.hpp"

namespace base::sdk::operators {
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
