#include "sdk/operator_animation.hpp"

namespace base::sdk::operators {
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

std::optional<ModuleLayout> AnimationModules(const Emulator::Program& code) {
    const auto& ins = code.instructions;
    ZydisRegister receiver = ZYDIS_REGISTER_NONE;
    for (std::size_t i = 0; i < std::min<std::size_t>(24, ins.size()); ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
            d.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER && d.operands[0].size == 64 &&
            Reg(d.operands[1], ZYDIS_REGISTER_RCX)) {
            if (receiver != ZYDIS_REGISTER_NONE)
                return std::nullopt;
            receiver = d.operands[0].reg.value;
        }
    }
    if (receiver == ZYDIS_REGISTER_NONE)
        return std::nullopt;

    struct Store {
        std::size_t instruction;
        std::uint32_t field;
        std::uint64_t crc;
    };

    std::vector<Store> stores;
    for (std::size_t i = 1; i + 2 < ins.size(); ++i) {
        const auto& call = ins[i];
        const auto& inverse = ins[i + 1];
        const auto& write = ins[i + 2];
        if (call.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
            call.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            inverse.instruction.mnemonic != ZYDIS_MNEMONIC_NOT ||
            !Reg(inverse.operands[0], ZYDIS_REGISTER_EAX) ||
            write.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || !Reg(write.operands[1], ZYDIS_REGISTER_EAX))
            continue;
        const auto& target = write.operands[0];
        const auto& seed = ins[i - 1];
        if (target.type != ZYDIS_OPERAND_TYPE_MEMORY || target.size != 32 || target.mem.base != receiver ||
            target.mem.index != ZYDIS_REGISTER_NONE || target.mem.disp.value < 0 ||
            target.mem.disp.value > 0x10000 || seed.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            !Reg(seed.operands[0], ZYDIS_REGISTER_EDX) ||
            seed.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
            static_cast<std::uint32_t>(seed.operands[1].imm.value.u) != 0xffffffffu)
            continue;
        std::uint64_t crc{};
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&call.instruction, &call.operands[0], call.address, &crc)))
            stores.push_back({i, static_cast<std::uint32_t>(target.mem.disp.value), crc});
    }
    if (stores.size() < 4 || stores[stores.size() - 2].crc != stores.back().crc ||
        stores[stores.size() - 2].field == stores.back().field)
        return std::nullopt;
    const auto checksum = stores[stores.size() - 2];
    const auto collection_begin = stores[stores.size() - 3].instruction + 3;

    std::set<std::uint32_t> arrays, primary;
    for (std::size_t i = collection_begin; i + 3 < checksum.instruction; ++i) {
        const auto& d = ins[i];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
            d.operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY || d.operands[1].mem.base != receiver ||
            d.operands[1].mem.index != ZYDIS_REGISTER_NONE || d.operands[1].mem.disp.value < 8 ||
            d.operands[1].mem.disp.value > 0x10000)
            continue;
        const auto field = static_cast<std::uint32_t>(d.operands[1].mem.disp.value);
        if (d.operands[1].size == 32 || d.operands[1].size == 64) {
            const auto& shift = ins[i + 1];
            const auto& mask = ins[i + 2];
            if (shift.instruction.mnemonic == ZYDIS_MNEMONIC_SHL &&
                Reg(shift.operands[0], d.operands[0].reg.value) &&
                shift.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                shift.operands[1].imm.value.u == 3 && mask.instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
                Reg(mask.operands[0], d.operands[0].reg.value))
                arrays.insert(field - 8);
        }
        if (d.operands[1].size == 64) {
            const auto wrapper = d.operands[0].reg.value;
            bool data{}, flags{};
            for (std::size_t k = i + 1; k < std::min(checksum.instruction, i + 24); ++k) {
                const auto& load = ins[k];
                if (load.instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                    load.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    load.operands[1].mem.base == wrapper && load.operands[1].mem.disp.value == 0 &&
                    load.operands[1].mem.index == ZYDIS_REGISTER_NONE && load.operands[1].size == 64)
                    data = true;
                if ((load.instruction.mnemonic == ZYDIS_MNEMONIC_MOVSXD ||
                        load.instruction.mnemonic == ZYDIS_MNEMONIC_AND) &&
                    load.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    load.operands[1].mem.base == wrapper && load.operands[1].mem.disp.value == 8 &&
                    load.operands[1].mem.index == ZYDIS_REGISTER_NONE)
                    flags = true;
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
                            branch->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            branch->operands[1].mem.base == wrapper &&
                            branch->operands[1].mem.disp.value == 0 &&
                            branch->operands[1].mem.index == ZYDIS_REGISTER_NONE &&
                            branch->operands[1].size == 64)
                            data = true;
                    }
                }
            }
            if (data && flags)
                primary.insert(field);
        }
    }
    if (arrays.size() != 1 || primary.size() != 1)
        return std::nullopt;
    std::map<std::uint32_t, std::pair<unsigned, std::size_t>> reads;
    for (std::size_t i = collection_begin; i < checksum.instruction; ++i) {
        const auto& d = ins[i];
        const auto& o = d.operands[1];
        if (d.instruction.mnemonic != ZYDIS_MNEMONIC_MOV ||
            d.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || o.type != ZYDIS_OPERAND_TYPE_MEMORY ||
            o.size != 32 || o.mem.index != ZYDIS_REGISTER_NONE || o.mem.base == receiver ||
            o.mem.base == ZYDIS_REGISTER_RSP || o.mem.base == ZYDIS_REGISTER_RIP || o.mem.disp.value < 0x20 ||
            o.mem.disp.value >= 0x400)
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
    if (repeated.size() < 2)
        return std::nullopt;
    const auto a = repeated[repeated.size() - 2].second, b = repeated.back().second;
    if (b != a + 4)
        return std::nullopt;
    return ModuleLayout{checksum.field, *primary.begin(), *arrays.begin(), *arrays.begin() + 8, a, 0, 8,
        code.begin, checksum.crc};
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
