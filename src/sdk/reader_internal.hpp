#pragma once
#include "sdk/reader.hpp"
#include "sdk/operators.hpp"
#include "sdk/operator_definitions.hpp"
#include "sdk/operator_animation.hpp"
#include "sdk/equipment.hpp"
#include "sdk/diagnostics.hpp"
#include "core/emulator.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <charconv>
#include <optional>
#include <limits>
#include <map>
#include <set>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace base::sdk {

using Address = std::uint64_t;

bool Pointer(Address value);

struct ReadFailure {
    DWORD error;
};

struct Environment {
    Address teb{}, tls{}, parent{}, manager{}, array{}, camera{};
    std::uint32_t count{};
};

bool Equivalent(const Environment& a, const Environment& b);

bool Finite(skeleton::Point p, float bound = 10000.0f);

bool Projection(const skeleton::Matrix& view);

struct Reader::Implementation {
    const Memory& process;
    ModuleInfo module;
    IMAGE_NT_HEADERS64 header;
    locators::NativeDescriptor native;
    std::optional<locators::MetadataDescriptor> metadata;
    std::optional<std::size_t> root_expression, camera_expression, manager_expression, array_expression;
    Emulator cpu;
    std::optional<EmulationResult> emulation_error;
    std::string message = "resolving live data";
    DWORD last_error = ERROR_SUCCESS;
    RuntimeDiagnostics trace;
    mutable std::array<std::optional<std::size_t>, 4> reported_paths;
    std::uint32_t tls_index{};
    std::vector<std::pair<Address, Address>> sections;
    std::optional<Environment> selected;
    std::chrono::steady_clock::time_point next_selection{};
    std::unordered_map<Address, std::uint32_t> hashes;
    std::unordered_map<Address, Address> extents;
    std::optional<std::size_t> operator_name_path;

    struct AnimationOperatorBinding {
        std::optional<operators::ModuleLayout> path;
        std::chrono::steady_clock::time_point retry{};
    };

    std::unordered_map<Address, AnimationOperatorBinding> animation_operators;
    std::unordered_map<Address, std::optional<equipment::ResourcePath>> weapon_paths;
    std::unordered_map<Address, std::optional<Emulator::Program>> equipment_methods;

    struct WeaponNamePath {
        Address object_offset{}, object_vtable{};
        locators::Expression data;
        Address serializer{}, dispatcher{}, descriptor{}, codec_field{}, codec{}, characters{};
    };

    struct WeaponNameSearch {
        std::optional<WeaponNamePath> path;
        std::chrono::steady_clock::time_point retry{};
    };

    std::unordered_map<Address, WeaponNameSearch> weapon_names;
    std::optional<std::array<std::uint8_t, 2>> defuser_values;
    Address defuser_teb{};
    std::chrono::steady_clock::time_point defuser_at{};
    unsigned invalid_poses{};
    unsigned ambiguous_bones{};
    unsigned discovery_budget{};
    Address discovery_cursor{};
    bool retry_discovery_first{};
    unsigned failures{};
    std::map<std::pair<Address, std::uint32_t>, std::optional<locators::MetadataDescriptor>> selection_arrays;
    Address context_manager{}, context_camera{};
    std::uint64_t epoch{};
    Address local_player{}, local_player_id{};
    Address local_profile{};
    std::optional<std::size_t> local_affiliation_path;

    struct LocalSideBinding {
        Address profile{}, profile_vtable{}, affiliation{}, side{}, side_vtable{}, manager{};
    };

    std::optional<LocalSideBinding> local_side;
    Address local_candidate{}, local_candidate_id{};
    unsigned local_confirmations{};

    struct CachedEntity {
        Address vtable{}, list{}, animation_component{}, transform_component{};
        std::int64_t component_offset{};
        std::uint32_t component_count{};
        std::uint32_t animation_index{}, transform_index{};
        Address local_role{}, team_source{}, team_parent{}, team_list{}, team_component{}, team_field{};
        Address username_component{};
        std::uint32_t username_index{};
        std::string username;
        Address name_profile{}, profile{};
        std::chrono::steady_clock::time_point profile_at{};
        std::optional<std::size_t> affiliation_path;
        std::chrono::steady_clock::time_point username_at{};
        std::optional<int> health;
        std::chrono::steady_clock::time_point health_at{};
        std::string weapon;
        std::chrono::steady_clock::time_point weapon_at{};
        std::uint32_t local_role_index{}, team_source_index{}, team_index{}, team_count{};
        Address team_list_offset{}, team_source_field{};
        Address team{};
        std::chrono::steady_clock::time_point team_at{}, next_team_attempt{};
        Address rig{}, names{};
        std::uint32_t pose_count{};
        std::vector<skeleton::PoseKey> keys;
        std::optional<skeleton::Binding> binding;
        std::optional<std::size_t> pose_path;
        std::optional<std::size_t> rig_path;
        std::chrono::steady_clock::time_point expires;
        std::chrono::steady_clock::time_point next_components{};
    };

    std::unordered_map<Address, CachedEntity> cache;
    std::set<Address> sampled_skeletons;

    struct Actor {
        Address entity;
        skeleton::Point origin;
        skeleton::Nodes nodes;
    };

    template <class T> T Read(Address at) {
        if (!Pointer(at) || sizeof(T) > 0x800000000000ull - at) {
            trace.Error("invalid_read_address", ERROR_INVALID_ADDRESS);
            throw ReadFailure{ERROR_INVALID_ADDRESS};
        }
        DWORD error = ERROR_SUCCESS;
        const auto value = process.Read<T>(static_cast<std::uintptr_t>(at), &error);
        if (!value) {
            trace.Error("memory_read_failed", error);
            throw ReadFailure{error};
        }
        return *value;
    }

    template <class T> std::vector<T> Array(Address at, std::size_t count) {
        if (!count || count > 0x10000 || !Pointer(at) || count * sizeof(T) > 0x800000000000ull - at) {
            trace.Error("invalid_array_bounds", ERROR_INVALID_DATA);
            throw ReadFailure{ERROR_INVALID_DATA};
        }
        std::vector<T> result(count);
        const auto got =
            process.ReadBytes(static_cast<std::uintptr_t>(at), std::as_writable_bytes(std::span(result)));
        if (!got.Complete()) {
            trace.Error("memory_array_read_failed", got.error);
            throw ReadFailure{got.error};
        }
        return result;
    }

    Address Q(Address at);

    Address Evaluate(const locators::PointerDescriptor& path, Address teb, Address object,
        std::string_view stage = {}, std::size_t index = 0);

    struct AnimationView {
        Address asset{}, buffer{}, rig{}, names{};
        std::uint32_t count{};
    };

    static constexpr std::size_t pose_stride = 0x20;

    AnimationView RigFor(CachedEntity& c);

    AnimationView AnimationFor(CachedEntity& c, const Environment& env);

    std::string EmulationMessage() const;

    bool Section(Address at) const;

    Implementation(const Memory& p, ModuleInfo m, IMAGE_NT_HEADERS64 h, locators::NativeDescriptor n);

    Environment Resolve(Address teb, Address tls);

    bool Select(std::stop_token stop);

    Address TypeInfo(Address object, Address* out_vtable = nullptr);

    std::uint32_t Hash(Address object);

    Address Extent(Address object, Address limit);

    CachedEntity Discover(Address entity);

    std::optional<int> HealthFor(Address entity, CachedEntity& c, const Environment& env);

    Address ProfileFor(Address entity, CachedEntity& c, const Environment& env);

    std::string UsernameFor(Address entity, CachedEntity& c, const Environment& env);

    bool SelectMetadata(const Environment& env, std::stop_token stop);

    std::uint32_t SelectedOperatorFor(Address entity, const CachedEntity& c);

    std::uint32_t AnimationOperatorFor(Address entity, const CachedEntity& c);

    std::uint32_t OperatorFor(Address entity, const CachedEntity& c);

    bool UnownedModelFor(Address entity, const CachedEntity& c);

    const std::optional<Emulator::Program>& EquipmentCode(Address method);

    std::string ResourceName(Address resource, const Environment& env);

    std::string WeaponFor(Address entity, CachedEntity& c, const Environment& env);

    std::optional<bool> DefuserFor(Address entity, const CachedEntity& c, const Environment& env);

    void ClearTeam(CachedEntity& c);

    void DiscoverTeam(CachedEntity& c);

    Address SideFor(Address entity, CachedEntity& c);

    Address AffiliationFor(Address profile, std::optional<std::size_t>& binding, const Environment& env);

    Address TeamFor(Address entity, CachedEntity& c, const Environment&);

    bool ValidLocalProfile(Address profile);

    Address LocalTeamFor(const Environment& env);

    std::optional<Actor> SkeletonFor(Address entity, const Environment& env);

    std::optional<Actor> CaptureSkeleton(Address entity, CachedEntity& c, const Environment& env);

    void IdentifyCameraBody(
        std::optional<skeleton::Point> eye, std::span<const Address> entries, const Environment& env);

    std::shared_ptr<const Snapshot> Poll(std::stop_token stop);
};
}
