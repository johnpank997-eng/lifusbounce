#pragma once
#include <Zydis/Zydis.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace base {
struct Instruction {
    std::uint64_t address;
    std::uint8_t length;
    std::string text;
};

struct Disassembly {
    std::vector<Instruction> instructions;
    std::size_t consumed = 0;
    ZyanStatus status = ZYAN_STATUS_SUCCESS;
};

[[nodiscard]] Disassembly Disassemble(std::span<const std::byte> bytes, std::uint64_t address,
    bool x64 = true, std::size_t max_instructions = 32);
}
