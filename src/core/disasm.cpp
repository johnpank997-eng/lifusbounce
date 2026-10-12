#include "core/disasm.hpp"

namespace base {
Disassembly Disassemble(
    std::span<const std::byte> bytes, std::uint64_t address, bool x64, std::size_t max_instructions) {
    Disassembly result;
    while (result.consumed < bytes.size() && result.instructions.size() < max_instructions) {
        ZydisDisassembledInstruction decoded{};
        result.status = ZydisDisassembleIntel(x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
            address + result.consumed, bytes.data() + result.consumed, bytes.size() - result.consumed,
            &decoded);
        if (!ZYAN_SUCCESS(result.status))
            break;
        result.instructions.push_back({address + result.consumed, decoded.info.length, decoded.text});
        result.consumed += decoded.info.length;
    }
    return result;
}
}
