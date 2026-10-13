#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::Poll(std::stop_token stop) -> std::shared_ptr<const Snapshot> {
    trace.Count("polls");
    last_error = ERROR_SUCCESS;
    emulation_error.reset();
    ambiguous_bones = 0;
    invalid_poses = 0;
    discovery_budget = 64;
    try {
        const auto now = std::chrono::steady_clock::now();
        if (!selected) {
            if (now < next_selection)
                return {};
            if (!Select(stop)) {
                trace.Count("selection_without_environment");
                next_selection = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
                if (emulation_error)
                    message = EmulationMessage();
                return {};
            }
        }
        auto env = Resolve(selected->teb, selected->tls);
        if (!metadata && !SelectMetadata(env, stop)) {
            selected.reset();
            return {};
        }
        if (env.manager != context_manager || env.camera != context_camera) {
            if (env.manager != context_manager) {
                cache.clear();
                hashes.clear();
                extents.clear();
                discovery_cursor = 0;
                local_player = 0;
                local_player_id = 0;
                local_profile = 0;
                local_affiliation_path.reset();
                local_side.reset();
                local_candidate = 0;
                local_candidate_id = 0;
                local_confirmations = 0;
            }
            context_manager = env.manager;
            context_camera = env.camera;
            ++epoch;
        }
        selected = env;
        auto frame = std::make_shared<Snapshot>();
        frame->camera = env.camera;
        frame->view_address = env.camera + 0x2c0;
        auto entries = Array<Address>(env.array, env.count);
        std::sort(entries.begin(), entries.end());
        entries.erase(std::unique(entries.begin(), entries.end()), entries.end());
        std::vector<Actor> actors;
        actors.reserve(std::min<std::size_t>(entries.size(), 64));
        const auto first = static_cast<std::size_t>(
            std::upper_bound(entries.begin(), entries.end(), discovery_cursor) - entries.begin());

        const auto discovery_until = std::chrono::steady_clock::now() + std::chrono::milliseconds(4);
        retry_discovery_first = !retry_discovery_first;
        for (unsigned pass = 0; pass < 2 && discovery_budget; ++pass)
            for (std::size_t index = 0; index < entries.size() && discovery_budget; ++index) {
                if (std::chrono::steady_clock::now() >= discovery_until)
                    break;
                const auto entity = entries[(first + index) % entries.size()];
                if (!Pointer(entity) || stop.stop_requested())
                    continue;
                const auto found = cache.find(entity);
                const bool retry = (pass == 0) == retry_discovery_first;
                if (!retry && found != cache.end())
                    continue;
                if (retry) {
                    if (found == cache.end())
                        continue;
                    const auto& c = found->second;
                    if (c.animation_component ? (c.username_component && c.local_role && c.team_source) ||
                                std::chrono::steady_clock::now() < c.next_components
                                              : std::chrono::steady_clock::now() < c.expires)
                        continue;
                }
                --discovery_budget;
                discovery_cursor = entity;
                try {
                    auto fresh = Discover(entity);
                    if (found != cache.end() && fresh.list == found->second.list &&
                        fresh.animation_component == found->second.animation_component &&
                        fresh.transform_component == found->second.transform_component &&
                        fresh.animation_component) {
                        auto& c = found->second;
                        c.local_role = fresh.local_role;
                        c.local_role_index = fresh.local_role_index;
                        if (c.team_source != fresh.team_source ||
                            c.team_source_index != fresh.team_source_index)
                            ClearTeam(c);
                        c.team_source = fresh.team_source;
                        c.team_source_index = fresh.team_source_index;
                        if (c.username_component != fresh.username_component) {
                            c.profile = c.name_profile = 0;
                            c.username.clear();
                            c.username_at = {};
                            c.affiliation_path.reset();
                        }
                        c.username_component = fresh.username_component;
                        c.username_index = fresh.username_index;
                        c.next_components = fresh.next_components;
                    } else
                        cache.insert_or_assign(entity, std::move(fresh));
                } catch (ReadFailure) {
                    if (found != cache.end() && found->second.animation_component)
                        found->second.next_components =
                            std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
                    else {
                        CachedEntity pending{};
                        pending.expires = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
                        cache.insert_or_assign(entity, std::move(pending));
                    }
                }
            }
        discovery_budget = 0;
        for (std::size_t index = 0; index < entries.size(); ++index) {
            const auto entity = entries[(first + index) % entries.size()];
            if (stop.stop_requested())
                return {};
            if (!Pointer(entity))
                continue;
            try {
                if (auto a = SkeletonFor(entity, env))
                    actors.push_back(std::move(*a));
            } catch (ReadFailure) {
                const auto retry = std::chrono::steady_clock::now();
                if (const auto found = cache.find(entity); found != cache.end()) {
                    if (found->second.expires <= retry)
                        found->second.expires = retry + std::chrono::milliseconds(50);
                } else {
                    CachedEntity c{};
                    c.expires = retry + std::chrono::milliseconds(250);
                    cache.emplace(entity, std::move(c));
                }
            }
        }

        for (const auto& [entity, c] : cache)
            if (c.animation_component && c.transform_component) {
                ++frame->players;
                if (c.rig && c.names && c.binding && !c.binding->ambiguous)
                    ++frame->initialized;
            }
        if (!frame->players && !entries.empty() &&
            std::all_of(entries.begin(), entries.end(),
                [&](Address entity) { return !Pointer(entity) || cache.contains(entity); })) {
            selected.reset();
            metadata.reset();
            root_expression.reset();
            manager_expression.reset();
            array_expression.reset();
            next_selection = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
            message = "waiting for player components";
            trace.Count("entity_array_without_player_components");
            return {};
        }
        const auto after = Resolve(env.teb, env.tls);
        if (!Equivalent(env, after)) {
            trace.Count("environment_changed_during_read");
            message = "game data changed; refreshing";
            return {};
        }
        frame->view = Read<skeleton::Matrix>(frame->view_address);
        IdentifyCameraBody(skeleton::Eye(frame->view), entries, env);
        std::erase_if(cache, [&](const auto& item) {
            return item.first != local_player &&
                !std::binary_search(entries.begin(), entries.end(), item.first);
        });
        frame->local_player = local_player;
        const auto local_team = LocalTeamFor(env);
        std::size_t teammates{};
        frame->entities.reserve(actors.size());
        for (auto& a : actors)
            if (a.entity != local_player) {
                Address team{};
                std::string username;
                std::optional<int> health;
                std::uint32_t operator_id{};
                std::string weapon;
                std::optional<bool> defuser;
                bool unowned_model{};
                if (const auto found = cache.find(a.entity); found != cache.end()) {
                    team = TeamFor(a.entity, found->second, env);
                    username = UsernameFor(a.entity, found->second, env);
                    health = HealthFor(a.entity, found->second, env);
                    operator_id = OperatorFor(a.entity, found->second);
                    weapon = WeaponFor(a.entity, found->second, env);
                    defuser = DefuserFor(a.entity, found->second, env);
                    unowned_model = UnownedModelFor(a.entity, found->second);
                }
                const bool same = local_team && team && team == local_team;
                teammates += same ? 1 : 0;
                frame->entities.push_back({std::move(a.nodes), same, local_team && team, a.entity, a.origin,
                    std::move(username), health, operator_id, std::move(weapon), defuser, unowned_model});
            }
        frame->presentation = !frame->local_player && !local_side && !frame->entities.empty() &&
            std::all_of(frame->entities.begin(), frame->entities.end(),
                [](const auto& body) { return body.unowned_model; });
        frame->captured = std::chrono::steady_clock::now();
        frame->present = std::move(entries);
        frame->epoch = epoch;
        if (frame->captured - now > std::chrono::milliseconds(200)) {
            trace.Count("frame_capture_over_200ms");
            message = "reading game data";
            return {};
        }
        message = frame->entities.empty() && ambiguous_bones ? "duplicate bone names"
            : frame->entities.empty() && invalid_poses
            ? "pose positions invalid"
            : "skeletons: " + std::to_string(frame->entities.size()) +
                " | teammates: " + std::to_string(teammates) + (local_team ? "" : " | team unknown");
        failures = 0;
        trace.Count("frames_published");
        return frame;
    } catch (ReadFailure failure) {
        trace.Error("poll_read_failure", failure.error);
        last_error = failure.error;
        message = emulation_error ? EmulationMessage() : "waiting for readable game data";
        if (++failures >= 3) {
            selected.reset();
            next_selection = {};
        }
        return {};
    }
}

Reader::Reader(
    const Memory& process, ModuleInfo module, IMAGE_NT_HEADERS64 header, locators::NativeDescriptor native) {
    try {
        impl_ = std::make_unique<Implementation>(process, std::move(module), header, std::move(native));
    } catch (ReadFailure failure) {
        throw std::system_error(
            static_cast<int>(failure.error), std::system_category(), "cannot initialize game data");
    }
}

Reader::~Reader() = default;

void Reader::Reload(ReloadTarget target) {
    auto& state = *impl_;
    if (target == ReloadTarget::skeletons) {
        for (auto& [entity, cached] : state.cache) {
            cached.rig = cached.names = 0;
            cached.pose_count = 0;
            cached.keys.clear();
            cached.binding.reset();
            cached.pose_path.reset();
            cached.expires = {};
        }
    } else {
        state.selected.reset();
        state.next_selection = {};
        state.root_expression.reset();
        state.manager_expression.reset();
        state.array_expression.reset();
        state.metadata.reset();
        state.cache.clear();
        state.operator_name_path.reset();
        state.animation_operators.clear();
        state.weapon_paths.clear();
        state.weapon_names.clear();
        state.equipment_methods.clear();
        state.hashes.clear();
        state.extents.clear();
        state.context_manager = 0;
        state.local_player = state.local_player_id = 0;
        state.local_profile = 0;
        state.local_affiliation_path.reset();
        state.local_side.reset();
        state.local_candidate = state.local_candidate_id = 0;
        state.local_confirmations = 0;
    }
    state.discovery_cursor = 0;
    state.failures = 0;
    state.last_error = ERROR_SUCCESS;
    state.emulation_error.reset();
    ++state.epoch;
}

std::shared_ptr<const Snapshot> Reader::Poll(std::stop_token stop) {
    return impl_->Poll(stop);
}

const std::string& Reader::Status() const noexcept {
    return impl_->message;
}

DWORD Reader::Error() const noexcept {
    return impl_->last_error;
}

std::uint64_t Reader::Epoch() const noexcept {
    return impl_->epoch;
}
}
