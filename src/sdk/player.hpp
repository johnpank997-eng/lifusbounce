#pragma once
#include "sdk/skeleton.hpp"
#include <chrono>
#include <span>
#include <string>
#include <optional>
#include <vector>

namespace base::sdk {
struct Player {
    skeleton::Nodes nodes;
    bool teammate{};
    bool team_known{};
    std::uintptr_t entity{};
    skeleton::Point origin{};
    std::string username;
    std::optional<int> health;
    std::uint32_t operator_id{};
    std::string weapon;
    std::optional<bool> defuser;
    bool unowned_model{};
};

struct Snapshot {
    skeleton::Matrix view{};
    std::uintptr_t camera{};
    std::uintptr_t view_address{};
    std::uintptr_t local_player{};
    std::uint32_t players{}, initialized{};
    std::vector<Player> entities;
    std::vector<std::uintptr_t> present;
    std::uint64_t epoch{};
    std::chrono::steady_clock::time_point captured;
    bool presentation{};

    [[nodiscard]] std::span<const Player> GetPlayers() const noexcept { return entities; }
};

}
