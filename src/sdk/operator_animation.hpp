#pragma once

#include "sdk/operator_native.hpp"
#include "sdk/operators.hpp"
#include <map>
#include <span>

namespace base::sdk::operators {
struct ModuleLayout {
    std::uint32_t checksum{}, primary{}, modules{}, count{}, signature{}, data{}, flags{};
    std::uint64_t producer{}, crc{};
    bool operator==(const ModuleLayout&) const = default;
};

bool Reg(const ZydisDecodedOperand& operand, ZydisRegister value);

std::optional<std::uint64_t> ReceiverCall(const Emulator::Program& method);

std::optional<ModuleLayout> AnimationModules(const Emulator::Program& code);

std::uint32_t AppendCrc(std::uint32_t state, std::uint32_t value) noexcept;

std::optional<std::uint32_t> BaseIdentity(std::span<const std::uint32_t> modules);
}
