#pragma once
#include "sdk/diagnostics.hpp"
#include <array>

namespace base::sdk {
enum class Feature { name, health, operator_id, team, weapon, defuser, count };

enum class FeatureStage {
    discovery,
    component,
    owner,
    profile,
    header,
    text,
    decode,
    value,
    instance,
    definition,
    reference,
    animation_layout,
    animation_modules,
    checksum,
    mapping,
    affiliation,
    resource,
    codec,
    flag,
    snapshot,
    count
};

enum class FeatureStatus {
    ready,
    cached,
    missing_path,
    ambiguous_path,
    missing_component,
    uninitialized,
    emulation_failed,
    read_failed,
    type_rejected,
    extent_rejected,
    invalid_layout,
    invalid_value,
    state_changed,
    mapping_missing,
    unavailable,
    count
};

struct FeatureEvidence {
    std::size_t path{};
    std::uint64_t entity{}, receiver{}, parent{}, address{}, field{}, extent{}, value{}, other{}, expected{},
        observed{};
    DWORD win32{};
    bool operator==(const FeatureEvidence&) const = default;
};

class FeatureDiagnostics {
  public:
    static constexpr unsigned ExampleLimit = 48, SuccessExampleLimit = 24, FailureExampleLimit = 24,
                              ReceiverLimit = 16, ReceiverSampleLimit = 32, ReceiverRetrySeconds = 30,
                              MetadataLimit = 16, VtableLimit = 16, OperatorVtableLimit = 64,
                              WeaponVtableLimit = 24, ReceiverBudgetMilliseconds = 8,
                              SnapshotUnavailableExampleLimit = 4;

    void BeginCapture() noexcept;
    void Record(Feature feature, FeatureStage stage, FeatureStatus status,
        const FeatureEvidence& evidence = {}) noexcept;
    void Receiver(const Memory& process, const ModuleInfo& module,
        std::span<const std::pair<std::uint64_t, std::uint64_t>> sections,
        std::span<const locators::MetadataDescriptor> metadata, Feature feature, FeatureStage stage,
        std::size_t path, std::uint64_t teb, std::uint64_t entity, std::uint64_t receiver) noexcept;
    void Report() const noexcept;

  private:
    static constexpr unsigned Features = static_cast<unsigned>(Feature::count),
                              Stages = static_cast<unsigned>(FeatureStage::count),
                              Statuses = static_cast<unsigned>(FeatureStatus::count);

    struct Example {
        FeatureStage stage{};
        FeatureStatus status{};
        FeatureEvidence evidence;
        bool operator==(const Example&) const = default;
    };

    struct ReceiverKey {
        FeatureStage stage{};
        std::size_t path{};
        std::uint64_t entity{}, receiver{};
        bool operator==(const ReceiverKey&) const = default;
    };

    std::array<std::array<std::array<std::uint64_t, Statuses>, Stages>, Features> counts_{};
    std::array<std::array<Example, ExampleLimit>, Features> examples_{};
    std::array<unsigned, Features> example_counts_{};
    std::array<std::array<unsigned, 2>, Features> example_classes_{};
    std::array<std::uint64_t, Features> discarded_examples_{};
    std::array<unsigned, Features> snapshot_unavailable_examples_{};
    std::array<std::uint64_t, Features> discarded_snapshot_unavailable_{};
    std::array<bool, Features> snapshot_limit_reported_{};
    std::array<std::array<bool, 2>, Features> example_limit_reported_{};
    std::array<std::array<ReceiverKey, ReceiverLimit>, Features> receivers_{};
    std::array<unsigned, Features> receiver_counts_{};
    std::array<std::array<std::chrono::steady_clock::time_point, ReceiverLimit>, Features> receiver_retry_{};
    std::array<std::array<std::chrono::steady_clock::time_point, ReceiverLimit>, Features> receiver_at_{};
    std::array<unsigned, Features> receiver_samples_{};
    std::array<std::uint64_t, Features> discarded_receivers_{};
    std::array<bool, Features> receiver_limit_reported_{};
    std::array<std::uint64_t, Features> receiver_budget_skips_{};
    std::chrono::steady_clock::time_point receiver_deadline_{};
    RuntimeDiagnostics metadata_trace_;
};
}
