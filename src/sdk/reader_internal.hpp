#pragma once
#include "sdk/reader.hpp"
#include "sdk/operators.hpp"
#include "sdk/operator_definitions.hpp"
#include "sdk/operator_animation.hpp"
#include "sdk/equipment.hpp"
#include "sdk/diagnostics.hpp"
#include "sdk/feature_diagnostics.hpp"
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

enum class ProjectionRejection : std::uint32_t {
    nonfinite = 1u << 0,
    axis0_zero = 1u << 1,
    axis1_zero = 1u << 2,
    axis2_zero = 1u << 3,
    axis3_zero = 1u << 4,
    dot01 = 1u << 5,
    dot03 = 1u << 6,
    dot13 = 1u << 7,
    dot23 = 1u << 8,
};

struct ProjectionEvidence {
    std::array<double, 4> lengths{};
    double dot01{}, dot03{}, dot13{}, dot23{};
    std::uint32_t rejections{};

    [[nodiscard]] bool Accepted() const noexcept { return rejections == 0; }
};

ProjectionEvidence InspectProjection(const skeleton::Matrix& view, bool transposed = false) noexcept;

std::optional<std::pair<std::uint64_t, std::uint64_t>> CameraDiagnosticReadBound(
    const Emulator::Program& code) noexcept;

bool Projection(const skeleton::Matrix& view);

enum class CameraPathOutcome : unsigned {
    emulation_failed,
    parent_not_pointer,
    parent_vtable_read_failed,
    parent_vtable_outside_image,
    object_slot_read_failed,
    object_not_pointer,
    matrix_read_failed,
    projection_rejected,
    camera_disagreed,
    verified,
};

struct CameraAttemptEvidence {
    std::size_t path{};
    Address teb{}, root{}, manager{}, array{}, parent{}, parent_vtable{}, camera{}, failing_address{};
    std::int64_t root_path{-1}, manager_path{-1}, array_path{-1};
    bool parent_vtable_read_complete{}, object_slot_read_complete{};
    std::optional<skeleton::Matrix> matrix;
    CameraPathOutcome outcome{};
    DWORD error{};
};

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
    FeatureDiagnostics feature_trace;
    static constexpr unsigned diagnostic_receiver_role_count = 4;
    static constexpr unsigned camera_sample_identity_limit = 16;
    static constexpr std::uint64_t camera_sample_read_call_limit = 64;
    static constexpr std::uint64_t camera_sample_read_byte_limit = 1408;
    static constexpr std::uint64_t camera_metadata_read_call_limit = 4096;
    static constexpr std::uint64_t camera_metadata_read_byte_limit = 65536;
    static constexpr unsigned camera_attempt_limit = 1024;
    std::array<std::array<Address, 16>, diagnostic_receiver_role_count> diagnostic_receivers{};
    std::array<unsigned, diagnostic_receiver_role_count> diagnostic_receiver_counts{};
    std::array<bool, diagnostic_receiver_role_count> diagnostic_receiver_limit_reported{};
    std::array<Address, camera_sample_identity_limit> camera_parent_samples{};
    std::array<std::pair<Address, Address>, camera_sample_identity_limit> camera_object_samples{};
    std::array<std::pair<Address, std::array<std::uint32_t, 16>>, camera_sample_identity_limit>
        camera_matrix_samples{};
    unsigned camera_parent_sample_count{}, camera_object_sample_count{}, camera_matrix_sample_count{};
    std::uint64_t camera_sample_read_calls{}, camera_sample_read_bytes{};
    std::uint64_t camera_metadata_read_calls{}, camera_metadata_read_bytes{};
    std::set<std::string_view> camera_diagnostic_limits_reported;
    using CameraAttemptKey = std::tuple<std::uint64_t, Address, Address, Address, Address, std::int64_t,
        std::int64_t, std::int64_t, std::size_t, CameraPathOutcome, Address, Address, bool, Address, bool,
        Address, bool, DWORD>;
    std::set<CameraAttemptKey> camera_attempts;
    bool camera_attempt_limit_reported{};
    std::optional<std::uint64_t> camera_screen_state_epoch;
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

    void ReportReceiverDiagnostics(
        std::string_view role, std::size_t path, Address teb, Address receiver) noexcept;

    bool ReserveCameraDiagnosticRead(
        std::string_view category, std::string_view stage, std::uint64_t calls, std::uint64_t bytes) noexcept;

    void ReportCameraDiagnosticBudget(std::string_view category, std::string_view reason,
        std::uint64_t requested_calls = 0, std::uint64_t requested_bytes = 0) noexcept;

    void ReportCameraDiagnosticLimit(
        std::string_view category, std::string_view reason, std::uint64_t used, std::uint64_t limit) noexcept;

    void ReportCameraDiagnosticSkip(std::string_view category, std::string_view reason) noexcept;

    void ReportCameraDiagnostics(const CameraAttemptEvidence& attempt) noexcept;

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
