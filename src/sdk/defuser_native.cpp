#include "sdk/equipment.hpp"

namespace base::sdk::equipment {
std::optional<OwnershipPath> DefuserOwner(const Emulator::Program& native) {
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
        return std::nullopt;
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
                return std::nullopt;
            begin = i + 1;
            input = ins[i].operands[0].reg.value;
        }
    if (begin == ins.size())
        return std::nullopt;
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
                return std::nullopt;
            if (stores && (path.object != o.mem.base || path.field != o.mem.disp.value))
                return std::nullopt;
            path.object = o.mem.base;
            path.field = static_cast<std::uint32_t>(o.mem.disp.value);
            ++stores;
            end = i + 1;
        }
    }

    if ((stores != 1 && stores != 2) || !tls || !rotation || path.object == ZYDIS_REGISTER_NONE)
        return std::nullopt;

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
}
