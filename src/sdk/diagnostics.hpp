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
    std::chrono::steady_clock::time_point checkpoint_at_{};
};

void ReportNative(const locators::NativeDescriptor& native, std::uint64_t module) noexcept;
bool ReportImage(const Memory& process, const ModuleInfo& module, const IMAGE_NT_HEADERS64& header,
    std::span<const std::byte> code, std::span<const locators::FunctionRecord> functions,
    std::string_view code_hash, std::stop_token stop) noexcept;
void ReportProgram(
    std::string_view role, std::size_t index, const Emulator::Program& code, std::uint64_t module) noexcept;

struct RuntimeDiagnostics {
    std::map<std::string_view, std::uint64_t> counters;
    std::set<std::tuple<std::string_view, std::size_t, unsigned, std::uint64_t>> examples;
    std::map<std::pair<std::string_view, std::size_t>, unsigned> executions;
    std::map<std::pair<std::string_view, std::size_t>, std::chrono::steady_clock::time_point> execution_retry;
    std::map<std::string_view, unsigned> execution_samples;
    std::set<std::string_view> successful_stages;
    unsigned captured_executions{};
    std::set<std::tuple<std::string_view, std::size_t, bool>> probes;
    void Probe(std::string_view stage, std::size_t index, std::uint64_t address, std::uint64_t value,
        bool accepted) noexcept;
    void Count(std::string_view name) noexcept;
    void Error(std::string_view stage, DWORD error) noexcept;
    bool Run(Emulator& cpu, const Emulator::Program& code, std::string_view stage, std::size_t index,
        std::uint64_t module);
    EmulationResult Execute(Emulator& cpu, const Emulator::Program& code, std::string_view stage,
        std::size_t index, std::uint64_t module);
    void Emulation(std::string_view stage, std::size_t index, const EmulationResult& result,
        std::uint64_t module) noexcept;
    void Report() const noexcept;
};
}
