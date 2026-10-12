#pragma once
#include "core/emulator.hpp"
#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace base::sdk::equipment {
struct ResourcePath {
    Emulator::Program code;
    ZydisRegister input{}, output{};
    std::uint32_t field{};
};

struct OwnershipPath {
    Emulator::Program encoder;
    ZydisRegister object{}, input{};
    std::uint32_t field{};
};

std::optional<OwnershipPath> DefuserOwner(const Emulator::Program& native);

std::optional<ResourcePath> WeaponResource(const Emulator::Program& native);

std::string WeaponName(std::string_view raw);
}
