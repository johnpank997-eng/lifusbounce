#pragma once
#include "sdk/locator.hpp"
#include <array>
#include <chrono>
#include <exception>
#include <map>
#include <set>
#include <tuple>

namespace base::sdk {
class DiscoveryDiagnostics {
  public:
    explicit DiscoveryDiagnostics(std::uint64_t module) : module_(module) {}

    void Observe(std::string_view role, const locators::FunctionRecord& function,
        std::span<const std::byte> bytes, const Emulator::Program* decoded, std::size_t accepted) noexcept;
    void Report() const noexcept;
    void Enter(std::string_view stage, std::size_t index, const locators::FunctionRecord& function) noexcept;
    void Validation(std::string_view rule, std::uint64_t instruction, std::uint64_t observed) noexcept;
    void Failure(const std::exception& error) const noexcept;

  private:
    struct Counts {
        std::uint64_t candidates{}, decoded{}, accepted{}, accepted_functions{}, examples{};
    };

    std::uint64_t module_;
    std::map<std::string_view, Counts> counts_;
    std::map<std::string_view, std::uint64_t> validations_;
    locators::FunctionRecord current_{};
    std::string_view stage_ = "scan";
    std::size_t index_{}, inventory_{}, validation_examples_{};
    std::array<unsigned, 6> feature_validation_examples_{};
    std::chrono::steady_clock::time_point checkpoint_at_{};
};

void ReportNative(const locators::NativeDescriptor& native, std::uint64_t module) noexcept;
bool ReportImage(const Memory& process, const ModuleInfo& module, const IMAGE_NT_HEADERS64& header,
    std::span<const std::byte> code, std::span<const locators::FunctionRecord> functions,
    std::string_view code_hash, std::stop_token stop) noexcept;
void ReportProgram(
    std::string_view role, std::size_t index, const Emulator::Program& code, std::uint64_t module) noexcept;

struct RuntimeDiagnostics {
    static constexpr unsigned ExecutionLimit = 512, ArrayInputLimit = 192, ExecutionFailureLimit = 64,
                              StageExecutionLimit = 8, ProbeLimit = 1024, ReadLimit = 128,
                              ArrayReceiverLimit = 16, ArrayReceiverExecutionLimit = 12,
                              ManagerOutputExecutionLimit = 32, ManagerRecipeExampleLimit = 128,
                              ArrayRecipeExampleLimit = 128, DiscardedRetryLimit = 4096,
                              ArrayEntryExampleLimit = 128, CameraExecutionReserve = 16;
    std::map<std::string_view, std::uint64_t> counters;
    std::set<std::tuple<std::string_view, std::size_t, unsigned, std::uint64_t>> examples;
    using ExecutionKey = std::tuple<std::string_view, std::size_t, std::uint64_t, std::uint64_t,
        std::array<std::uint64_t, 16>, std::array<std::array<std::uint64_t, 2>, 16>, std::uint64_t,
        std::uint64_t, std::array<std::uint64_t, 2>, std::uint64_t>;
    std::map<ExecutionKey, unsigned> executions;
    std::map<ExecutionKey, std::chrono::steady_clock::time_point> execution_retry;
    std::map<ExecutionKey, std::chrono::steady_clock::time_point> discarded_execution_retry;
    std::chrono::steady_clock::time_point discarded_retry_at{};
    std::map<std::string_view, unsigned> execution_samples;
    std::set<std::tuple<std::string_view, unsigned, std::uint64_t, ZydisMnemonic>> execution_failures;
    std::set<std::string_view> successful_stages;
    std::map<std::uint64_t, unsigned> array_receiver_executions;
    std::map<std::uint64_t, unsigned> array_receiver_priority_executions;
    std::set<ExecutionKey> manager_output_executions;
    using ManagerRecipeKey = std::tuple<std::string_view, std::size_t, std::uint64_t, std::uint64_t>;
    std::set<ManagerRecipeKey> manager_recipe_examples;
    using ArrayRecipeKey = std::tuple<std::uint64_t, std::size_t, std::uint64_t, std::uint64_t>;
    std::set<ArrayRecipeKey> array_recipe_examples;
    using ArrayEntryKey = std::tuple<std::size_t, std::uint64_t, std::uint64_t, unsigned, unsigned, DWORD>;
    std::set<ArrayEntryKey> array_entry_examples;
    unsigned array_executions{};
    unsigned array_priority_executions{};
    unsigned captured_executions{};
    unsigned observed_executions{};
    unsigned discarded_executions{};
    std::set<std::tuple<std::string_view, std::size_t, bool, std::uint64_t>> probes;
    void Probe(std::string_view stage, std::size_t index, std::uint64_t address, std::uint64_t value,
        bool accepted, std::uint64_t owner = 0) noexcept;
    void Count(std::string_view name) noexcept;
    void Error(std::string_view stage, DWORD error) noexcept;
    void ArrayEntry(std::size_t index, std::uint64_t manager, std::uint64_t entries, unsigned ordinal,
        std::uint64_t value, std::uint64_t vtable, bool entry_read_complete, bool vtable_read_complete,
        bool pointer_accepted, bool type_accepted, DWORD error) noexcept;
    bool Run(Emulator& cpu, const Emulator::Program& code, std::string_view stage, std::size_t index,
        std::uint64_t module, std::uint64_t array_receiver = 0,
        ZydisRegister manager_output = ZYDIS_REGISTER_NONE);
    EmulationResult Execute(Emulator& cpu, const Emulator::Program& code, std::string_view stage,
        std::size_t index, std::uint64_t module, std::uint64_t array_receiver = 0,
        ZydisRegister manager_output = ZYDIS_REGISTER_NONE);
    void Emulation(std::string_view stage, std::size_t index, const EmulationResult& result,
        std::uint64_t module) noexcept;
    void Report() const noexcept;
};
}
