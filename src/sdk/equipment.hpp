#pragma once
#include "core/emulator.hpp"
#include <algorithm>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace base::sdk::equipment {
struct ResourcePath {
    Emulator::Program code;
    ZydisRegister input{}, output{};
    std::uint32_t field{};
};

struct OwnershipSeed {
    Emulator::Program code;
    ZydisRegister output{}, target{};
    std::int64_t slot{};
    bool stack{};
};

struct OwnershipPath {
    Emulator::Program encoder;
    ZydisRegister object{}, input{};
    std::uint32_t field{};
    std::vector<OwnershipSeed> seeds;
};

using ValidationObserver = std::function<void(std::string_view, std::uint64_t, std::uint64_t)>;
std::optional<OwnershipPath> DefuserOwner(
    const Emulator::Program& native, const ValidationObserver& validation = {});

std::optional<ResourcePath> WeaponResource(const Emulator::Program& native);

std::string WeaponName(std::string_view raw);
}
