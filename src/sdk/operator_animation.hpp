#pragma once

#include "sdk/operator_native.hpp"
#include "sdk/operators.hpp"
#include <map>
#include <span>

namespace base::sdk::operators {
struct ModuleLayout {
    std::uint32_t checksum{}, primary{}, modules{}, count{}, signature{}, data{}, flags{};
    std::uint64_t producer{}, crc{};
    std::uint64_t count_mask = 0x3fffffff;
    std::uint32_t count_width = 32;
    std::uint32_t checksum_high{}, count_shift_width = 32;
    std::uint64_t count_consumer{}, count_direct_consumer{}, count_mask_store{};
    std::int64_t count_mask_slot{};
    std::uint32_t count_direct_width = 32, count_direct_shift_width = 32;
    std::uint64_t count_byte_mask{};
    bool operator==(const ModuleLayout&) const = default;
};

enum class ModuleRejection { none, receiver, aliases, checksum, collection, signature };

struct ModuleDiscovery {
    ModuleRejection rejection{};
    std::size_t stores{}, arrays{}, primary{}, repeated{};
};

bool Reg(const ZydisDecodedOperand& operand, ZydisRegister value);

std::optional<std::uint64_t> ReceiverCall(const Emulator::Program& method);

std::optional<ModuleLayout> AnimationModules(const Emulator::Program& code,
    const std::function<std::optional<std::int32_t>(std::uint64_t)>& read = {},
    ModuleDiscovery* discovery = nullptr, std::uint64_t source_end = 0);

std::uint32_t AppendCrc(std::uint32_t state, std::uint32_t value) noexcept;

std::optional<std::uint32_t> BaseIdentity(std::span<const std::uint32_t> modules);
}
