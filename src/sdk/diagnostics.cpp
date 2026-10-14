#include "sdk/diagnostics.hpp"
#include "core/diagnostics.hpp"
#include <algorithm>

namespace base::sdk {
namespace {
std::string Register(ZydisRegister reg) {
    const auto text = ZydisRegisterGetString(reg);
    return text ? text : "none";
}

void Expression(
    std::string_view role, std::size_t index, const locators::Expression& value, std::uint64_t module) {
    diagnostics::Write("native_expression",
        {{"role", role}, {"index", index}, {"input_mask", value.inputs}, {"output", Register(value.output)}});
    ReportProgram(role, index, value.code, module);
}

void Pointer(std::string_view role, std::size_t index, const locators::PointerDescriptor& value,
    std::uint64_t module) {
    diagnostics::Write("native_pointer",
        {{"role", role}, {"index", index}, {"input", Register(value.input.reg)},
            {"input_stack", value.input.stack}, {"input_slot", value.input.slot},
            {"output", Register(value.output.reg)}, {"output_stack", value.output.stack},
            {"output_slot", value.output.slot}, {"seeds", value.seeds.size()}});
    ReportProgram(role, index, value.code, module);
    for (std::size_t i = 0; i < std::min<std::size_t>(value.seeds.size(), 8); ++i) {
        diagnostics::Write("native_pointer_seed",
            {{"role", role}, {"index", index}, {"seed_index", i},
                {"target", Register(value.seeds[i].target.reg)},
                {"target_stack", value.seeds[i].target.stack}, {"target_slot", value.seeds[i].target.slot}});
        const auto seed_role = role == "pose_asset" ? "pose_asset_seed"
            : role == "pose_buffer"                 ? "pose_buffer_seed"
            : role == "operator_instance"           ? "operator_instance_seed"
            : role == "operator_definition"         ? "operator_definition_seed"
            : role == "operator_name_reference"     ? "operator_name_reference_seed"
                                                    : "pointer_seed";
        Expression(seed_role, index * 32 + i, value.seeds[i].value, module);
    }
}
}

void ReportProgram(
    std::string_view role, std::size_t index, const Emulator::Program& code, std::uint64_t module) noexcept {
    try {
        if (!diagnostics::Enabled())
            return;
        diagnostics::Write("native_program",
            {{"role", role}, {"index", index}, {"begin_rva", diagnostics::Hex(code.begin - module)},
                {"end_rva", diagnostics::Hex(code.end - module)}, {"instructions", code.instructions.size()},
                {"linear", code.linear}, {"sparse", code.sparse}, {"instruction_limit", 48u}});
        ZydisFormatter formatter{};
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
        const auto size = code.instructions.size();
        for (std::size_t at = 0; at < size; ++at) {
            if (size > 48 && at == 24)
                at = size - 24;
            const auto& instruction = code.instructions[at];
            std::array<char, 320> text{};
            const auto formatted = ZydisFormatterFormatInstruction(&formatter, &instruction.instruction,
                instruction.operands.data(), instruction.instruction.operand_count_visible, text.data(),
                text.size(), instruction.address - module, nullptr);
            diagnostics::Write("native_instruction",
                {{"role", role}, {"index", index}, {"ordinal", at},
                    {"rva", diagnostics::Hex(instruction.address - module)},
                    {"text", ZYAN_SUCCESS(formatted) ? text.data() : "format unavailable"}});
        }
    } catch (...) {
    }
}

void DiscoveryDiagnostics::Observe(std::string_view role, const locators::FunctionRecord& function,
    std::span<const std::byte> bytes, const Emulator::Program* decoded, std::size_t accepted) noexcept {
    try {
        auto& count = counts_[role];
        ++count.candidates;
        count.decoded += decoded ? 1 : 0;
        count.accepted += accepted;
        count.accepted_functions += accepted ? 1 : 0;
        if (decoded && (role == "root_context" || (role == "pose" && (accepted || count.examples < 6)))) {
            unsigned calls{};
            for (const auto& instruction : decoded->instructions) {
                if (instruction.instruction.mnemonic != ZYDIS_MNEMONIC_CALL ||
                    instruction.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE ||
                    !instruction.operands[0].imm.is_relative || calls++ >= 64)
                    continue;
                const auto target = instruction.address + instruction.instruction.length +
                    instruction.operands[0].imm.value.s;
                diagnostics::Write("native_helper_edge",
                    {{"role", role}, {"function_rva", diagnostics::Hex(function.begin)},
                        {"call_rva", diagnostics::Hex(instruction.address - module_)},
                        {"target_rva",
                            target >= module_ ? diagnostics::Hex(target - module_) : "outside image"}});
            }
        }
        if ((role == "root_context" || role == "pose" || accepted) && inventory_ < 20000) {
            ++inventory_;
            diagnostics::Write("discovery_result",
                {{"role", role}, {"begin_rva", diagnostics::Hex(function.begin)},
                    {"end_rva", diagnostics::Hex(function.end)}, {"decoded", decoded != nullptr},
                    {"accepted_descriptors", accepted}, {"function_index", index_}});
        }
        if (count.examples >= 6)
            return;
        ++count.examples;
        const auto hash = diagnostics::Sha256(bytes);
        diagnostics::Write("discovery_candidate",
            {{"role", role}, {"begin_rva", diagnostics::Hex(function.begin)},
                {"end_rva", diagnostics::Hex(function.end)}, {"native_sha256", hash},
                {"sampled_bytes", bytes.size()}, {"decoded", decoded != nullptr},
                {"accepted_descriptors", accepted},
                {"outcome",
                    !decoded       ? "native decode rejected"
                        : accepted ? "accepted"
                                   : "semantic proof rejected"}});
        if (decoded && !accepted && role == "root_context") {
            diagnostics::Write("root_function_detail",
                {{"instructions", decoded->instructions.size()}, {"code_artifact_required", true}});
            const auto& code = *decoded;
            ZydisFormatter formatter{};
            ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
            for (std::size_t i = 0; i < std::min<std::size_t>(code.instructions.size(), 8192); ++i) {
                const auto& instruction = code.instructions[i];
                std::array<char, 320> text{};
                const auto formatted = ZydisFormatterFormatInstruction(&formatter, &instruction.instruction,
                    instruction.operands.data(), instruction.instruction.operand_count_visible, text.data(),
                    text.size(), instruction.address - module_, nullptr);
                diagnostics::Write("root_instruction",
                    {{"function_rva", diagnostics::Hex(function.begin)}, {"ordinal", i},
                        {"rva", diagnostics::Hex(instruction.address - module_)},
                        {"text", ZYAN_SUCCESS(formatted) ? text.data() : "format unavailable"}});
            }
        }
        if (decoded && !accepted)
            ReportProgram(role, count.examples - 1, *decoded, module_);
    } catch (...) {
    }
}

void DiscoveryDiagnostics::Report() const noexcept {
    for (const auto& [role, count] : counts_)
        diagnostics::Write("discovery_role",
            {{"role", role}, {"candidates", count.candidates}, {"decoded", count.decoded},
                {"accepted_descriptors", count.accepted},
                {"decode_rejected", count.candidates - count.decoded},
                {"semantic_rejected", count.decoded - count.accepted_functions},
                {"examples", count.examples}});
    for (const auto& [rule, count] : validations_)
        diagnostics::Write("validation_count", {{"rule", rule}, {"count", count}});
    diagnostics::Write("discovery_inventory",
        {{"records", inventory_}, {"limit", 20000u}, {"complete", inventory_ < 20000},
            {"validation_examples", validation_examples_}});
    constexpr std::array roles{
        "owner profile", "name", "health", "operator common asset", "selected character", "defuser"};
    for (std::size_t i = 0; i < roles.size(); ++i)
        diagnostics::Write("feature_validation_summary",
            {{"stage", roles[i]}, {"examples", feature_validation_examples_[i]}, {"limit", 256u},
                {"complete", feature_validation_examples_[i] < 256}});
}

void DiscoveryDiagnostics::Enter(
    std::string_view stage, std::size_t index, const locators::FunctionRecord& function) noexcept {
    stage_ = stage;
    index_ = index;
    current_ = function;
    const auto now = std::chrono::steady_clock::now();
    if (now - checkpoint_at_ >= std::chrono::seconds(1)) {
        checkpoint_at_ = now;
        try {
            diagnostics::Write("scan_checkpoint",
                {{"stage", stage}, {"function_index", index}, {"begin_rva", diagnostics::Hex(function.begin)},
                    {"end_rva", diagnostics::Hex(function.end)}});
        } catch (...) {
        }
    }
}

void DiscoveryDiagnostics::Validation(
    std::string_view rule, std::uint64_t instruction, std::uint64_t observed) noexcept {
    try {
        ++validations_[rule];
        constexpr std::array<std::string_view, 6> roles{
            "owner profile", "name", "health", "operator common asset", "selected character", "defuser"};
        const auto role = std::find(roles.begin(), roles.end(), stage_);
        if (role != roles.end()) {
            auto& examples = feature_validation_examples_[role - roles.begin()];
            if (examples >= 256)
                return;
            ++examples;
        } else {
            if (validation_examples_ >= 4000)
                return;
            ++validation_examples_;
        }
        diagnostics::Write("discovery_validation",
            {{"rule", rule}, {"stage", stage_}, {"function_rva", diagnostics::Hex(current_.begin)},
                {"instruction_rva", diagnostics::Hex(instruction - module_)},
                {"observed", diagnostics::Hex(observed)}, {"function_index", index_}});
    } catch (...) {
    }
}

void DiscoveryDiagnostics::Failure(const std::exception& error) const noexcept {
    try {
        diagnostics::Write("scan_exception_context",
            {{"stage", stage_}, {"function_index", index_}, {"begin_rva", diagnostics::Hex(current_.begin)},
                {"end_rva", diagnostics::Hex(current_.end)}});
        diagnostics::Exception("native discovery", error);
        Report();
    } catch (...) {
    }
}

void ReportNative(const locators::NativeDescriptor& native, std::uint64_t module) noexcept {
    try {
        diagnostics::Write("native_summary",
            {{"roots", native.roots.size()}, {"contexts", native.contexts.size()},
                {"cameras", native.cameras.size()}, {"managers", native.managers.size()},
                {"arrays", native.arrays.size()}, {"metadata", native.metadata.size()},
                {"rigs", native.rigs.size()}, {"poses", native.poses.size()},
                {"usernames", native.usernames.size()}, {"ownership", native.ownership.size()},
                {"health", native.health.size()}, {"affiliations", native.affiliations.size()},
                {"operator_names", native.operator_names.size()},
                {"selected_operator", native.selected_operator.has_value()},
                {"defuser", native.defuser.has_value()},
                {"local_profile_field", native.local_profile_field.value_or(0)},
                {"descriptor_limit_per_role", 64u}});
        const auto expressions = [&](std::string_view role, const auto& values) {
            for (std::size_t i = 0; i < std::min<std::size_t>(values.size(), 64); ++i)
                Expression(role, i, values[i], module);
        };
        expressions("root", native.roots);
        expressions("context", native.contexts);
        expressions("camera", native.cameras);
        expressions("manager", native.managers);
        for (std::size_t i = 0; i < std::min<std::size_t>(native.metadata.size(), 64); ++i) {
            const auto& value = native.metadata[i];
            diagnostics::Write("metadata_recipe",
                {{"index", i}, {"table_field", diagnostics::Hex(value.table_field)},
                    {"hash_field", diagnostics::Hex(value.hash_field)}});
            Expression("metadata", i, value.decode, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.arrays.size(), 64); ++i) {
            const auto& value = native.arrays[i];
            diagnostics::Write("array_recipe",
                {{"index", i}, {"input", Register(value.input)}, {"array", Register(value.array)},
                    {"count", Register(value.count)}, {"count_mask", diagnostics::Hex(value.count_mask)}});
            if (value.caller_slot)
                diagnostics::Write("array_caller_context",
                    {{"index", i}, {"slot", *value.caller_slot},
                        {"caller_rva", diagnostics::Hex(value.caller - module)}});
            ReportProgram("array", i, value.code, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.rigs.size(), 64); ++i) {
            const auto& value = native.rigs[i];
            diagnostics::Write("rig_recipe",
                {{"index", i}, {"names_field", diagnostics::Hex(value.names_field)},
                    {"count_width", value.count_width}, {"record_stride", 8u}, {"index_field", 4u}});
            Expression("rig", i, value.owner, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.poses.size(), 64); ++i) {
            Pointer("pose_asset", i, native.poses[i].asset, module);
            Pointer("pose_buffer", i, native.poses[i].buffer, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.ownership.size(), 64); ++i) {
            diagnostics::Write("ownership_recipe",
                {{"index", i}, {"owner_type_rva", diagnostics::Hex(native.ownership[i].owner_type - module)},
                    {"profile_type_rva", diagnostics::Hex(native.ownership[i].profile_type - module)}});
            Expression("owner", i, native.ownership[i].owner, module);
            Expression("owner_profile", i, native.ownership[i].profile, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.usernames.size(), 64); ++i) {
            const auto& value = native.usernames[i];
            diagnostics::Write("username_recipe",
                {{"index", i}, {"owner_type_rva", diagnostics::Hex(value.owner_type - module)},
                    {"profile_type_rva", diagnostics::Hex(value.profile_type - module)},
                    {"string_field", diagnostics::Hex(value.string_field)}, {"character_capture", false}});
            Expression("username_owner", i, value.owner, module);
            Expression("username_profile", i, value.profile, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.health.size(), 64); ++i) {
            const auto& value = native.health[i];
            diagnostics::Write("health_recipe",
                {{"index", i}, {"maximum", Register(value.maximum)}, {"current", Register(value.current)}});
            ReportProgram("health", i, value.code, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.affiliations.size(), 64); ++i) {
            const auto& value = native.affiliations[i];
            diagnostics::Write("affiliation_recipe",
                {{"index", i}, {"profile", Register(value.profile)}, {"field", diagnostics::Hex(value.field)},
                    {"null_value", diagnostics::Hex(value.null_value)},
                    {"pointer_identity", value.pointer_identity}});
            Expression("affiliation", i, value.object, module);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(native.operator_names.size(), 64); ++i) {
            const auto& value = native.operator_names[i];
            diagnostics::Write("operator_name_recipe",
                {{"index", i}, {"field", diagnostics::Hex(value.field)},
                    {"consumer_rva", diagnostics::Hex(value.consumer - module)},
                    {"target_type_rva", diagnostics::Hex(value.target_type - module)}});
            Pointer("operator_name_reference", i, value.reference, module);
        }
        if (native.selected_operator) {
            const auto& value = *native.selected_operator;
            diagnostics::Write("selected_operator_recipe",
                {{"instance_field", diagnostics::Hex(value.instance_field)},
                    {"definition_field", diagnostics::Hex(value.definition_field)},
                    {"consumer_rva", diagnostics::Hex(value.consumer - module)},
                    {"definition_type_rva", diagnostics::Hex(value.definition_type - module)}});
            Pointer("operator_instance", 0, value.instance, module);
            Pointer("operator_definition", 0, value.definition, module);
        }
        if (native.defuser) {
            const auto& value = *native.defuser;
            diagnostics::Write("defuser_recipe",
                {{"field", diagnostics::Hex(value.field)}, {"object", Register(value.object)},
                    {"input", Register(value.input)}, {"seeds", value.seeds.size()},
                    {"write_scope", "private emulator stack"}});
            ReportProgram("defuser_encoder", 0, value.encoder, module);
            for (std::size_t i = 0; i < std::min<std::size_t>(value.seeds.size(), 64); ++i) {
                const auto& seed = value.seeds[i];
                diagnostics::Write("defuser_seed_recipe",
                    {{"index", i}, {"output", Register(seed.output)}, {"target", Register(seed.target)},
                        {"stack", seed.stack}, {"slot", seed.slot}});
                ReportProgram("defuser_encoder_seed", i, seed.code, module);
            }
        }
        const auto feature = [&](std::string_view name, std::size_t count, bool unique) {
            diagnostics::Write("native_feature_support",
                {{"feature", name}, {"candidates", count},
                    {"discovery_status",
                        !count                     ? "missing path"
                            : unique && count != 1 ? "ambiguous path"
                                                   : "candidate available"},
                    {"runtime_validated", false}});
        };
        feature("name", native.usernames.size(), true);
        feature("health", native.health.size(), true);
        feature("operator primary", native.selected_operator ? 1 : 0, true);
        feature("operator common asset", native.operator_names.size(), false);
        feature("team affiliation", native.affiliations.size(), false);
        feature("defuser", native.defuser ? 1 : 0, true);
        diagnostics::Write("fixed_layout_assumptions",
            {{"camera_parent_field", "0xf00"}, {"camera_matrix_field", "0x2c0"}, {"pose_stride", "0x20"},
                {"metadata_extent_field", "0x24"}, {"subtype_lower_field", "0x40"},
                {"subtype_upper_field", "0x42"}});
        diagnostics::Write("feature_layout_assumptions",
            {{"team_source_parent_field", "0x48"}, {"weapon_source_parent_field", "0x48"},
                {"reference_payload_field", 0u}, {"reference_flags_field", 8u},
                {"reference_initialized_mask", "0x80000000"}, {"string_header_bytes", 16u},
                {"name_maximum_bytes", 256u}, {"weapon_maximum_bytes", 24u},
                {"health_maximum_exclusive_lower", 20u}, {"health_maximum_exclusive_upper", 300u},
                {"weapon_methods_limit", 24u}, {"operator_methods_limit", 64u},
                {"heap_string_contents_captured", false}});
    } catch (...) {
    }
}

void RuntimeDiagnostics::Count(std::string_view name) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        if (++counters[name] == 1)
            diagnostics::Write("runtime_first_seen", {{"reason", name}});
    } catch (...) {
    }
}

void RuntimeDiagnostics::Probe(std::string_view stage, std::size_t index, std::uint64_t address,
    std::uint64_t value, bool accepted, std::uint64_t owner) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        if (probes.size() < ProbeLimit && probes.emplace(stage, index, accepted, owner).second)
            diagnostics::Write("runtime_probe",
                {{"stage", stage}, {"path_index", index}, {"address", diagnostics::Hex(address)},
                    {"value", diagnostics::Hex(value)}, {"accepted", accepted},
                    {"owner", diagnostics::Hex(owner)}});
    } catch (...) {
    }
}

void RuntimeDiagnostics::Error(std::string_view stage, DWORD error) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        Count(stage);
        if (examples.size() < 128 && examples.emplace(stage, 0, error, 0).second)
            diagnostics::Write("runtime_read_error", {{"stage", stage}, {"win32", error}});
    } catch (...) {
    }
}

bool RuntimeDiagnostics::Run(Emulator& cpu, const Emulator::Program& code, std::string_view stage,
    std::size_t index, std::uint64_t module, std::uint64_t array_receiver, ZydisRegister manager_output) {
    const auto result = Execute(cpu, code, stage, index, module, array_receiver, manager_output);
    if (result.Complete())
        return true;
    Emulation(stage, index, result, module);
    return false;
}

void RuntimeDiagnostics::Emulation(
    std::string_view stage, std::size_t index, const EmulationResult& result, std::uint64_t module) noexcept {
    if (!diagnostics::Enabled())
        return;
    Count(stage);
    try {
        if (examples.size() < 128 &&
            examples.emplace(stage, index, static_cast<unsigned>(result.status), result.address).second) {
            const auto mnemonic = ZydisMnemonicGetString(result.mnemonic);
            constexpr std::array names{"complete", "unsupported", "invalid operand", "read failed",
                "write blocked", "control flow", "budget exhausted"};
            const auto status = static_cast<std::size_t>(result.status);
            diagnostics::Write("runtime_emulation_error",
                {{"stage", stage}, {"path_index", index}, {"rva", diagnostics::Hex(result.address - module)},
                    {"mnemonic", mnemonic ? mnemonic : "unknown"},
                    {"status", static_cast<unsigned>(result.status)},
                    {"status_name", status < names.size() ? names[status] : "unknown"},
                    {"steps", result.steps}});
        }
    } catch (...) {
    }
}

void RuntimeDiagnostics::Report() const noexcept {
    for (const auto& [name, count] : counters)
        diagnostics::Write("runtime_counter", {{"reason", name}, {"count", count}});
    diagnostics::Write("runtime_evidence_summary",
        {{"executions", captured_executions}, {"execution_limit", ExecutionLimit},
            {"reads_per_execution_limit", ReadLimit}, {"stage_execution_limit", StageExecutionLimit},
            {"array_input_executions", array_executions}, {"array_input_limit", ArrayInputLimit},
            {"array_receiver_identities", array_receiver_executions.size()},
            {"array_receiver_limit", ArrayReceiverLimit},
            {"array_receiver_execution_limit", ArrayReceiverExecutionLimit},
            {"manager_output_executions", manager_output_executions.size()},
            {"manager_output_execution_limit", ManagerOutputExecutionLimit},
            {"manager_output_budget_remaining",
                ManagerOutputExecutionLimit - manager_output_executions.size()},
            {"manager_recipe_examples", manager_recipe_examples.size()},
            {"manager_recipe_example_limit", ManagerRecipeExampleLimit},
            {"manager_recipe_budget_remaining", ManagerRecipeExampleLimit - manager_recipe_examples.size()},
            {"distinct_failures", execution_failures.size()},
            {"distinct_failure_limit", ExecutionFailureLimit}, {"execution_keys", executions.size()},
            {"execution_key_limit", ExecutionLimit}, {"observed_executions", observed_executions},
            {"discarded_executions", discarded_executions}, {"probes", probes.size()},
            {"probe_limit", ProbeLimit}, {"retry_seconds", 30u},
            {"input_key", "registers vectors gs flags stack fingerprint array receiver"},
            {"execution_budget_remaining", ExecutionLimit - captured_executions},
            {"array_input_budget_remaining", ArrayInputLimit - array_executions},
            {"distinct_failure_budget_remaining", ExecutionFailureLimit - execution_failures.size()},
            {"additional_execution_capacity", captured_executions < ExecutionLimit}});
    for (const auto& [receiver, count] : array_receiver_executions)
        diagnostics::Write("array_receiver_evidence_summary",
            {{"receiver", diagnostics::Hex(receiver)}, {"executions", count},
                {"execution_limit", ArrayReceiverExecutionLimit},
                {"execution_budget_remaining", ArrayReceiverExecutionLimit - count},
                {"receiver_role_verified", false}});
}
}
