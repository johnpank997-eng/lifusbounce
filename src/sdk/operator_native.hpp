#pragma once
#include "core/emulator.hpp"
#include <algorithm>
#include <optional>
#include <set>
#include <functional>
#include <map>

namespace base::sdk::operators {
struct SharedMember {
    std::uint32_t field{};
    std::uint64_t producer{}, copy{};
    bool operator==(const SharedMember&) const = default;
};

std::vector<SharedMember> SharedMembers(const Emulator::Program& method);

struct StackProvenance {
    std::array<std::optional<std::int64_t>, 16> sources{};
    std::map<std::int64_t, std::pair<std::uint64_t, std::uint64_t>> assignments;
    bool operator==(const StackProvenance&) const = default;
};

std::vector<std::uint16_t> ReceiverBindings(const Emulator::Program& method, std::size_t begin,
    std::size_t complete, const std::function<std::optional<std::int32_t>(std::uint64_t)>& read,
    std::uint64_t source_end = 0, std::vector<std::vector<std::size_t>>* edges = nullptr,
    std::vector<std::array<std::optional<std::uint64_t>, 16>>* values = nullptr,
    std::vector<std::map<std::int64_t, std::uint64_t>>* locals = nullptr,
    std::vector<StackProvenance>* provenance = nullptr);

}
