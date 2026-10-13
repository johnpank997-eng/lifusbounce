#pragma once
#include "core/mem.hpp"
#include <Zydis/Zydis.h>
#include <array>
#include <optional>
#include <span>
#include <vector>

namespace base {
enum class EmulationStatus {
    complete,
    unsupported,
    invalid_operand,
    read_failed,
    write_blocked,
    control_flow,
    budget_exhausted
};

struct EmulationResult {
    EmulationStatus status{};
    std::uint64_t address{};
    ZydisMnemonic mnemonic{};
    std::size_t steps{};

    [[nodiscard]] bool Complete() const noexcept { return status == EmulationStatus::complete; }
};

class Emulator {
  public:
    struct Access {
        std::uint64_t instruction{}, address{}, value{};
        unsigned bits{};
        DWORD error{};
        bool supplied{}, stack{};
    };

    struct Observer {
        void* context{};
        void (*read)(void*, const Access&) noexcept {};
    };

    struct State {
        std::array<std::uint64_t, 16> registers{};
        std::array<std::array<std::uint64_t, 2>, 16> vectors{};
        std::uint64_t gs{}, flags{};
    };

    struct Decoded {
        std::uint64_t address{};
        ZydisDecodedInstruction instruction{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
    };

    struct Program {
        std::uint64_t begin{}, end{};
        std::vector<Decoded> instructions;
        bool linear{};
        bool sparse{};
    };

    explicit Emulator(const Memory& process) : process_(process) {}

    [[nodiscard]] static std::optional<Program> Decode(
        std::span<const std::byte> bytes, std::uint64_t address, bool prefix = false);
    void Reset(std::uint64_t teb = 0) noexcept;
    void Set(ZydisRegister reg, std::uint64_t value);
    [[nodiscard]] std::uint64_t Get(ZydisRegister reg) const;
    void Stack(std::uint32_t offset, std::uint64_t value);
    [[nodiscard]] std::uint64_t Stack(std::uint32_t offset) const;
    void Input(std::uint64_t address, std::span<const std::byte> bytes);
    [[nodiscard]] EmulationResult Run(const Program& code, std::size_t budget = 2048);

    void Observe(Observer observer) noexcept { observer_ = observer; }

    [[nodiscard]] State Snapshot() const noexcept { return {registers_, vectors_, gs_, flags_}; }

    [[nodiscard]] std::span<const std::byte> StackData() const noexcept { return stack_; }

  private:
    struct Region {
        std::uint64_t address;
        std::span<const std::byte> bytes;
    };

    static constexpr std::uint64_t stack_base = 0x70000000000ull;
    const Memory& process_;
    std::array<std::uint64_t, 16> registers_{};
    std::array<std::array<std::uint64_t, 2>, 16> vectors_{};
    std::array<std::byte, 0x10000> stack_{};
    std::vector<Region> inputs_;
    std::uint64_t ip_{}, next_{}, gs_{}, flags_{2};
    std::uint64_t current_{};
    unsigned address_width_{64};
    Observer observer_{};
    [[nodiscard]] std::uint64_t Address(const ZydisDecodedOperand& operand, bool segment = true) const;
    [[nodiscard]] std::uint64_t Load(std::uint64_t address, unsigned bits) const;
    void Store(std::uint64_t address, unsigned bits, std::uint64_t value);
    [[nodiscard]] std::uint64_t Value(const ZydisDecodedOperand& operand) const;
    void Write(const ZydisDecodedOperand& operand, std::uint64_t value);
    void Arithmetic(std::uint64_t a, std::uint64_t b, std::uint64_t result, unsigned bits, bool subtract);
    void Logical(std::uint64_t result, unsigned bits);
    [[nodiscard]] std::optional<bool> Condition(ZydisMnemonic mnemonic) const;
    void Step(const Decoded& instruction);
};
}
