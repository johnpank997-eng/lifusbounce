#include "sdk/equipment.hpp"

namespace base::sdk::equipment {
std::optional<ResourcePath> WeaponResource(const Emulator::Program& native) {
    ZydisRegister source = ZYDIS_REGISTER_NONE;
    unsigned copies{};
    std::optional<ResourcePath> result;
    const auto& ins = native.instructions;
    for (std::size_t i = 0; i + 1 < ins.size(); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_RET)
            break;
        if (!source && d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 64 &&
            d.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            d.operands[1].reg.value == ZYDIS_REGISTER_RCX)
            source = d.operands[0].reg.value;
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || d.operands[1].mem.base != source ||
            d.operands[1].mem.index != ZYDIS_REGISTER_NONE)
            continue;
        const auto& next = ins[i + 1];
        const auto field = d.operands[1].mem.disp.value;
        if (field >= 0x98 && field <= 0xae && (d.operands[1].size == 8 || d.operands[1].size == 32) &&
            next.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            next.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && next.operands[0].mem.base != source &&
            next.operands[0].mem.disp.value == field &&
            next.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            next.operands[1].reg.value == d.operands[0].reg.value)
            ++copies;
        if (copies < 4 || d.operands[1].size != 64 || field < 0x40 || field >= 0x98 ||
            (next.instruction.mnemonic != ZYDIS_MNEMONIC_ROL &&
                next.instruction.mnemonic != ZYDIS_MNEMONIC_ROR) ||
            next.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || next.operands[0].size != 64 ||
            next.operands[0].reg.value != d.operands[0].reg.value ||
            next.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
            continue;
        if (result)
            return std::nullopt;
        result = ResourcePath{{d.address, next.address + next.instruction.length, {d, next}, true}, source,
            d.operands[0].reg.value, static_cast<std::uint32_t>(field)};
    }
    return result;
}

std::string WeaponName(std::string_view raw) {
    const auto end = raw.find('\0');
    if (end == std::string_view::npos || end < 2 || end > 24)
        return {};
    raw = raw.substr(0, end);
    while (!raw.empty() && raw.front() == '!')
        raw.remove_prefix(1);
    if (raw.size() < 2)
        return {};
    for (char c : raw)
        if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' &&
            c != '_' && c != ' ')
            return {};
    if (raw == "MAC11")
        return "SMG-11";
    if (raw == "JS9")
        return "T-5 SMG";
    if (raw == "SMG_STORMMX4" || raw == "STORMMX4")
        return "Mx4 Storm";
    return std::string(raw);
}
}
