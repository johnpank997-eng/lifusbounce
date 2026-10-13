#pragma once
#include "sdk/locator.hpp"
#include <array>
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

  private:
    struct Counts {
        std::uint64_t candidates{}, decoded{}, accepted{}, accepted_functions{}, examples{};
    };

    std::uint64_t module_;
    std::map<std::string_view, Counts> counts_;
};

void ReportNative(const locators::NativeDescriptor& native, std::uint64_t module) noexcept;
void ReportProgram(
    std::string_view role, std::size_t index, const Emulator::Program& code, std::uint64_t module) noexcept;

struct RuntimeDiagnostics {
    std::map<std::string_view, std::uint64_t> counters;
    std::set<std::tuple<std::string_view, std::size_t, unsigned, std::uint64_t>> examples;
    void Count(std::string_view name) noexcept;
    void Error(std::string_view stage, DWORD error) noexcept;
    bool Run(Emulator& cpu, const Emulator::Program& code, std::string_view stage, std::size_t index,
        std::uint64_t module);
    void Emulation(std::string_view stage, std::size_t index, const EmulationResult& result,
        std::uint64_t module) noexcept;
    void Report() const noexcept;
};
}
