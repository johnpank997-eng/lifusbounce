#include "sdk/diagnostics.hpp"
#include "core/diagnostics.hpp"
#include <atomic>
#include <cstring>

namespace base::sdk {
namespace {
struct ExecutionReads {
    std::array<Emulator::Access, RuntimeDiagnostics::ReadLimit> reads{};
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

std::array<std::uint64_t, 2> StackKey(std::span<const std::byte> bytes) {
    std::array<std::uint64_t, 2> result{0xcbf29ce484222325ull, 0x9e3779b97f4a7c15ull};
    for (std::size_t i = 0; i < bytes.size(); i += sizeof(std::uint64_t)) {
        std::uint64_t value{};
        std::memcpy(&value, bytes.data() + i, sizeof(value));
        result[0] = (result[0] ^ value) * 0x100000001b3ull;
        result[1] = (result[1] + value) * 0x9e3779b185ebca87ull;
    }
    return result;
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
    std::string_view stage, std::size_t index, std::uint64_t module, std::uint64_t array_receiver,
    ZydisRegister manager_output) {
    bool observe{};
    ExecutionKey key;
    Emulator::State before{};
    std::uint64_t manager_before{};
    const bool receiver_array = stage == "array_emulation_failed" && array_receiver != 0;
    const bool manager_hint = stage == "manager_emulation_failed" && manager_output >= ZYDIS_REGISTER_RAX &&
        manager_output <= ZYDIS_REGISTER_R15 && manager_output != ZYDIS_REGISTER_RSP;
    const ManagerRecipeKey manager_recipe{stage, index, code.begin, code.end};
    const bool manager_recipe_first = stage == "manager_emulation_failed" &&
        manager_recipe_examples.size() < ManagerRecipeExampleLimit &&
        !manager_recipe_examples.contains(manager_recipe);
    const ArrayRecipeKey array_recipe{array_receiver, index, code.begin, code.end};
    const bool array_recipe_first = receiver_array &&
        array_recipe_examples.size() < ArrayRecipeExampleLimit &&
        !array_recipe_examples.contains(array_recipe);
    const auto receiver_samples = array_receiver_executions.find(array_receiver);
    const bool receiver_identity_capacity = receiver_samples != array_receiver_executions.end() ||
        array_receiver_executions.size() < ArrayReceiverLimit;
    const bool receiver_capacity = receiver_samples == array_receiver_executions.end()
        ? array_receiver_executions.size() < ArrayReceiverLimit
        : receiver_samples->second < ArrayReceiverExecutionLimit;
    const bool array_normal_capacity = receiver_capacity && array_executions < ArrayInputLimit;
    const bool array_priority = array_recipe_first && receiver_identity_capacity && !array_normal_capacity;
    try {
        const auto samples = execution_samples.find(stage);
        const bool stage_capacity =
            samples == execution_samples.end() || samples->second < StageExecutionLimit;
        const auto now = std::chrono::steady_clock::now();
        if (diagnostics::Enabled() && captured_executions < ExecutionLimit &&
            (now >= discarded_retry_at || stage_capacity || manager_recipe_first || array_recipe_first) &&
            (!receiver_array || array_normal_capacity || array_priority) &&
            (stage_capacity || !successful_stages.contains(stage) ||
                execution_failures.size() < ExecutionFailureLimit ||
                (stage == "array_emulation_failed" && array_executions < ArrayInputLimit) ||
                manager_recipe_first || array_priority ||
                (manager_hint && manager_output_executions.size() < ManagerOutputExecutionLimit))) {
            before = cpu.Snapshot();
            if (manager_hint)
                manager_before = cpu.Get(manager_output);
            key = {stage, index, code.begin, code.end, before.registers, before.vectors, before.gs,
                before.flags, StackKey(cpu.StackData()), receiver_array ? array_receiver : 0};
            const auto retry = execution_retry.find(key);
            const auto discarded = discarded_execution_retry.find(key);
            observe = (retry == execution_retry.end() || now >= retry->second) &&
                (discarded == discarded_execution_retry.end() || now >= discarded->second);
        }
    } catch (...) {
    }
    if (!observe)
        return cpu.Run(code);
    ++observed_executions;
    ExecutionReads collected;
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
        const auto prior = executions.find(key);
        const unsigned flags = prior == executions.end() ? 0 : prior->second;
        const unsigned bit = result.Complete() ? 2u : 1u;
        const bool first_success = result.Complete() && !successful_stages.contains(stage);
        const bool distinct_failure = !result.Complete() &&
            execution_failures.size() < ExecutionFailureLimit &&
            !execution_failures.contains(
                {stage, static_cast<unsigned>(result.status), result.address, result.mnemonic});
        const bool array_input = stage == "array_emulation_failed" && array_executions < ArrayInputLimit &&
            (!receiver_array || receiver_capacity) && !(flags & bit);
        const auto samples = execution_samples.find(stage);
        const bool stage_capacity =
            samples == execution_samples.end() || samples->second < StageExecutionLimit;
        const auto manager_value = manager_hint ? cpu.Get(manager_output) : 0;
        const bool manager_canonical = manager_hint && result.Complete() && manager_value >= 0x10000 &&
            manager_value <= 0x7fffffffffffull && manager_value != manager_before;
        const bool manager_priority = result.Complete() && manager_canonical && !(flags & bit) &&
            !stage_capacity && !manager_recipe_first &&
            manager_output_executions.size() < ManagerOutputExecutionLimit &&
            !manager_output_executions.contains(key);
        const bool keep = (!receiver_array || array_normal_capacity || array_priority) &&
            (distinct_failure || array_input || array_priority || manager_recipe_first || manager_priority ||
                (!(flags & bit) && (first_success || stage_capacity)));
        const auto retry_at = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        if (prior != executions.end())
            execution_retry[key] = retry_at;
        if (!keep) {
            ++discarded_executions;
            if (prior == executions.end()) {
                if (discarded_execution_retry.contains(key) ||
                    discarded_execution_retry.size() < DiscardedRetryLimit)
                    discarded_execution_retry[key] = retry_at;
                else
                    discarded_retry_at = retry_at;
            }
            return result;
        }
        executions[key] = flags | bit;
        execution_retry[key] = retry_at;
        discarded_execution_retry.erase(key);
        if (array_input || (receiver_array && !array_priority))
            ++array_executions;
        if (receiver_array) {
            auto& receiver_count = array_receiver_executions[array_receiver];
            if (!array_priority)
                ++receiver_count;
            if (array_recipe_first)
                array_recipe_examples.emplace(array_recipe);
        }
        if (array_priority) {
            ++array_priority_executions;
            ++array_receiver_priority_executions[array_receiver];
        }
        if (manager_priority)
            manager_output_executions.emplace(key);
        if (manager_recipe_first)
            manager_recipe_examples.emplace(manager_recipe);
        if (distinct_failure)
            execution_failures.emplace(
                stage, static_cast<unsigned>(result.status), result.address, result.mnemonic);
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
                {"steps", result.steps}, {"stop_rva", diagnostics::Hex(result.address - module)},
                {"array_receiver", diagnostics::Hex(receiver_array ? array_receiver : 0)},
                {"array_recipe_first", array_recipe_first}, {"array_recipe_priority", array_priority},
                {"manager_output_register", manager_hint ? ZydisRegisterGetString(manager_output) : "none"},
                {"manager_output_value", diagnostics::Hex(manager_value)},
                {"manager_output_canonical_hint", manager_canonical},
                {"manager_recipe_first", manager_recipe_first}, {"manager_output_priority", manager_priority},
                {"receiver_role_verified", false}});
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
