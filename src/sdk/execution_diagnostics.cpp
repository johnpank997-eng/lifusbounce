#include "sdk/diagnostics.hpp"
#include "core/diagnostics.hpp"
#include <atomic>
#include <cstring>

namespace base::sdk {
namespace {
struct ExecutionReads {
    std::array<Emulator::Access, 128> reads{};
    unsigned count{}, total{};
};

struct Observation {
    Emulator& cpu;

    ~Observation() { cpu.Observe({}); }
};

void Number(std::vector<std::byte>& bytes, std::uint64_t value, unsigned width = 8) {
    for (unsigned i = 0; i < width; ++i)
        bytes.push_back(std::byte((value >> (i * 8)) & 255));
}

std::string Key(std::string_view name, std::span<const std::byte> bytes) {
    return std::string(name) + ":0x0:" + diagnostics::Sha256(bytes);
}

std::vector<std::byte> Program(const Emulator::Program& code, std::uint64_t module) {
    std::vector<std::byte> bytes;
    for (const auto& decoded : code.instructions) {
        const auto& instruction = decoded.instruction;
        Number(bytes, decoded.address - module);
        Number(bytes, instruction.mnemonic, 4);
        Number(bytes, instruction.length, 1);
        Number(bytes, instruction.address_width, 1);
        Number(bytes, instruction.operand_count, 1);
        Number(bytes, instruction.operand_count_visible, 1);
        Number(bytes, instruction.attributes);
        Number(bytes, instruction.meta.category, 4);
        for (unsigned i = 0; i < instruction.operand_count; ++i) {
            const auto& operand = decoded.operands[i];
            Number(bytes, operand.type, 1);
            Number(bytes, operand.size, 2);
            Number(bytes, operand.actions, 1);
            switch (operand.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                Number(bytes, operand.reg.value, 4);
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                Number(bytes, operand.mem.type, 1);
                Number(bytes, operand.mem.segment, 4);
                Number(bytes, operand.mem.base, 4);
                Number(bytes, operand.mem.index, 4);
                Number(bytes, operand.mem.scale, 1);
                Number(bytes, operand.mem.disp.has_displacement, 1);
                Number(bytes, operand.mem.disp.value);
                break;
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                Number(bytes, (operand.imm.is_signed ? 1 : 0) | (operand.imm.is_relative ? 2 : 0), 1);
                Number(bytes, operand.imm.value.u);
                break;
            case ZYDIS_OPERAND_TYPE_POINTER:
                Number(bytes, operand.ptr.segment, 2);
                Number(bytes, operand.ptr.offset, 4);
                break;
            default:
                break;
            }
        }
    }
    return bytes;
}
}

EmulationResult RuntimeDiagnostics::Execute(Emulator& cpu, const Emulator::Program& code,
    std::string_view stage, std::size_t index, std::uint64_t module) {
    bool observe{};
    try {
        const auto key = std::pair{stage, index};
        observe = diagnostics::Enabled() && captured_executions < 128 && executions.size() < 1024 &&
            executions[key] != 3 && std::chrono::steady_clock::now() >= execution_retry[key];
    } catch (...) {
    }
    if (!observe)
        return cpu.Run(code);
    ExecutionReads collected;
    const auto before = cpu.Snapshot();
    std::array<std::byte, 0x10000> stack{};
    std::memcpy(stack.data(), cpu.StackData().data(), stack.size());
    Observation observation{cpu};
    cpu.Observe({&collected, [](void* context, const Emulator::Access& access) noexcept {
                     auto& collector = *static_cast<ExecutionReads*>(context);
                     ++collector.total;
                     if (collector.count < collector.reads.size())
                         collector.reads[collector.count++] = access;
                 }});
    EmulationResult result{};
    try {
        result = cpu.Run(code);
    } catch (const std::exception& error) {
        diagnostics::Write("execution_exception",
            {{"stage", stage}, {"path_index", index},
                {"program_begin_rva", diagnostics::Hex(code.begin - module)}, {"reads", collected.total}});
        diagnostics::Exception("emulator execution", error);
        throw;
    }
    cpu.Observe({});
    try {
        auto& flags = executions[{stage, index}];
        execution_retry[{stage, index}] = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        const unsigned bit = result.Complete() ? 2u : 1u;
        const bool first_success = result.Complete() && !successful_stages.contains(stage);
        const bool keep = !(flags & bit) && (first_success || execution_samples[stage] < 8);
        flags |= bit;
        if (!keep)
            return result;
        if (result.Complete())
            successful_stages.emplace(stage);
        ++execution_samples[stage];
        ++captured_executions;
        static std::atomic<std::uint64_t> sequence{};
        const auto id = ++sequence;
        std::vector<std::byte> state, output, reads;
        const auto instructions = Program(code, module);
        state.reserve(400);
        for (const auto value : before.registers)
            Number(state, value);
        for (const auto& value : before.vectors)
            for (const auto part : value)
                Number(state, part);
        Number(state, before.gs);
        Number(state, before.flags);
        const auto after = cpu.Snapshot();
        for (const auto value : after.registers)
            Number(output, value);
        for (const auto& value : after.vectors)
            for (const auto part : value)
                Number(output, part);
        Number(output, after.gs);
        Number(output, after.flags);
        for (unsigned i = 0; i < collected.count; ++i) {
            const auto& access = collected.reads[i];
            Number(reads, access.instruction - module);
            Number(reads, access.address);
            Number(reads, access.value);
            Number(reads, access.bits, 4);
            Number(reads, access.error, 4);
            Number(reads, access.stack ? 1 : access.supplied ? 2 : 0, 1);
        }
        diagnostics::Write("execution_begin",
            {{"id", id}, {"stage", stage}, {"path_index", index}, {"module_base", diagnostics::Hex(module)},
                {"program_begin_rva", diagnostics::Hex(code.begin - module)},
                {"program_end_rva", diagnostics::Hex(code.end - module)}, {"linear", code.linear},
                {"sparse", code.sparse}, {"instruction_count", code.instructions.size()},
                {"state_artifact", Key("execution_state", state)},
                {"output_artifact", Key("execution_output", output)},
                {"stack_artifact", Key("execution_stack", stack)},
                {"reads_artifact", Key("execution_reads", reads)},
                {"instructions_artifact", Key("execution_program", instructions)}, {"program_format", 1u},
                {"read_record_bytes", 33u}, {"reads_captured", collected.count},
                {"reads_total", collected.total}, {"status", static_cast<unsigned>(result.status)},
                {"steps", result.steps}, {"stop_rva", diagnostics::Hex(result.address - module)}});
        const bool complete = diagnostics::Artifact("execution_state", 0, state) &&
            diagnostics::Artifact("execution_output", 0, output) &&
            diagnostics::Artifact("execution_stack", 0, stack) &&
            diagnostics::Artifact("execution_reads", 0, reads) &&
            diagnostics::Artifact("execution_program", 0, instructions);
        diagnostics::Write("execution_end",
            {{"id", id}, {"artifacts_complete", complete},
                {"reads_complete", collected.count == collected.total},
                {"replay_inputs_complete", complete && collected.count == collected.total}});
    } catch (const std::exception& error) {
        diagnostics::Exception("execution evidence", error);
    }
    return result;
}
}
