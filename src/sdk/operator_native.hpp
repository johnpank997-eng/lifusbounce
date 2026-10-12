#pragma once
#include "core/emulator.hpp"
#include <algorithm>
#include <optional>
#include <set>

namespace base::sdk::operators {
struct SharedMember {
    std::uint32_t field{};
    std::uint64_t producer{}, copy{};
    bool operator==(const SharedMember&) const = default;
};

std::vector<SharedMember> SharedMembers(const Emulator::Program& method);

}
