#include "sdk/reader_internal.hpp"
#include "core/diagnostics.hpp"

namespace base::sdk {
void Reader::Implementation::ReportReceiverDiagnostics(
    std::string_view role, std::size_t path, Address teb, Address receiver) noexcept {
    if (!diagnostics::Enabled() || !Pointer(receiver) || sizeof(Address) > 0x800000000000ull - receiver)
        return;
    try {
        const auto role_index = role == "root" ? 0u : 1u;
        auto& receivers = diagnostic_receivers[role_index];
        auto& receiver_count = diagnostic_receiver_counts[role_index];
        if (std::find(receivers.begin(), receivers.begin() + receiver_count, receiver) !=
            receivers.begin() + receiver_count)
            return;
        if (receiver_count >= receivers.size()) {
            if (!diagnostic_receiver_limit_reported[role_index]) {
                diagnostic_receiver_limit_reported[role_index] = true;
                diagnostics::Write("receiver_diagnostic_limit",
                    {{"role", role}, {"path_index", path}, {"teb", diagnostics::Hex(teb)},
                        {"receiver", diagnostics::Hex(receiver)}, {"receiver_limit", 16u},
                        {"metadata_recipe_limit", 16u}, {"complete", false}});
            }
            return;
        }
        receivers[receiver_count++] = receiver;
        DWORD vtable_error{};
        const auto vtable = process.Read<Address>(receiver, &vtable_error);
        const auto table_valid = vtable && Pointer(*vtable) && Section(*vtable);
        diagnostics::Write("receiver_diagnostic_begin",
            {{"role", role}, {"sample", receiver_count - 1}, {"path_index", path},
                {"teb", diagnostics::Hex(teb)}, {"receiver", diagnostics::Hex(receiver)},
                {"vtable", diagnostics::Hex(vtable.value_or(0))},
                {"vtable_read_complete", vtable.has_value()}, {"vtable_win32", vtable_error},
                {"vtable_in_image_section", table_valid}, {"metadata_recipes", native.metadata.size()},
                {"receiver_limit", 16u}, {"metadata_recipe_limit", 16u}, {"selected_by_reader", false}});
        if (!table_valid) {
            diagnostics::Write("receiver_diagnostic_end",
                {{"role", role}, {"receiver", diagnostics::Hex(receiver)}, {"recipes_attempted", 0u},
                    {"complete", false}, {"reason", "vtable read or section check failed"}});
            return;
        }
        const auto recipes = std::min<std::size_t>(native.metadata.size(), 16);
        Emulator diagnostic_cpu(process);
        for (std::size_t index = 0; index < recipes; ++index) {
            const auto& recipe = native.metadata[index];
            const auto link_address = *vtable + recipe.table_field;
            DWORD link_error = ERROR_INVALID_ADDRESS;
            std::optional<Address> info;
            if (Pointer(link_address) && Section(link_address) && Section(link_address + sizeof(Address) - 1))
                info = process.Read<Address>(link_address, &link_error);
            const bool info_valid = info && Pointer(*info) && Section(*info);
            DWORD hash_error = ERROR_INVALID_ADDRESS, extent_error = ERROR_INVALID_ADDRESS,
                  low_error = ERROR_INVALID_ADDRESS, high_error = ERROR_INVALID_ADDRESS;
            std::optional<std::uint32_t> encoded_hash;
            std::optional<Address> extent;
            std::optional<std::uint16_t> low, high;
            EmulationResult result{EmulationStatus::read_failed};
            bool decode_attempted{};
            std::uint32_t hash{};
            if (info_valid) {
                if (Section(*info + recipe.hash_field) && Section(*info + recipe.hash_field + 3))
                    encoded_hash = process.Read<std::uint32_t>(*info + recipe.hash_field, &hash_error);
                if (Section(*info + 0x24) && Section(*info + 0x2b))
                    extent = process.Read<Address>(*info + 0x24, &extent_error);
                if (Section(*info + 0x40) && Section(*info + 0x41))
                    low = process.Read<std::uint16_t>(*info + 0x40, &low_error);
                if (Section(*info + 0x42) && Section(*info + 0x43))
                    high = process.Read<std::uint16_t>(*info + 0x42, &high_error);
                diagnostic_cpu.Reset(teb);
                diagnostic_cpu.Set(ZYDIS_REGISTER_RCX, receiver);
                decode_attempted = true;
                result = trace.Execute(
                    diagnostic_cpu, recipe.decode.code, "receiver_metadata_decode", index, module.address);
                if (result.Complete())
                    hash = static_cast<std::uint32_t>(diagnostic_cpu.Get(recipe.decode.output));
            }
            DWORD receiver_reread_error{}, link_reread_error = ERROR_INVALID_ADDRESS;
            const auto receiver_reread = process.Read<Address>(receiver, &receiver_reread_error);
            std::optional<Address> link_reread;
            if (Pointer(link_address) && Section(link_address) && Section(link_address + sizeof(Address) - 1))
                link_reread = process.Read<Address>(link_address, &link_reread_error);
            const bool receiver_stable = receiver_reread && *receiver_reread == *vtable;
            const bool link_stable = info && link_reread && *link_reread == *info;
            const bool complete = info_valid && encoded_hash && extent && low && high && result.Complete() &&
                receiver_stable && link_stable;
            diagnostics::Write("receiver_metadata_candidate",
                {{"role", role}, {"path_index", path}, {"teb", diagnostics::Hex(teb)},
                    {"receiver", diagnostics::Hex(receiver)}, {"recipe_index", index},
                    {"vtable", diagnostics::Hex(*vtable)}, {"table_field", recipe.table_field},
                    {"hash_field", recipe.hash_field}, {"link_address", diagnostics::Hex(link_address)},
                    {"metadata", diagnostics::Hex(info.value_or(0))},
                    {"link_read_complete", info.has_value()}, {"link_win32", link_error},
                    {"metadata_in_image_section", info_valid},
                    {"encoded_hash", diagnostics::Hex(encoded_hash.value_or(0))},
                    {"encoded_hash_read_complete", encoded_hash.has_value()},
                    {"encoded_hash_win32", hash_error}, {"extent", extent.value_or(0)},
                    {"extent_read_complete", extent.has_value()}, {"extent_win32", extent_error},
                    {"subtype_lower", low ? static_cast<int>(*low) : -1}, {"subtype_lower_win32", low_error},
                    {"subtype_upper", high ? static_cast<int>(*high) : -1},
                    {"subtype_upper_win32", high_error}, {"interval_read_complete", low && high},
                    {"decode_attempted", decode_attempted}, {"decode_complete", result.Complete()},
                    {"decode_status", static_cast<unsigned>(result.status)}, {"decode_steps", result.steps},
                    {"decode_stop_rva",
                        result.address >= module.address ? diagnostics::Hex(result.address - module.address)
                                                         : "outside image"},
                    {"decode_mnemonic", ZydisMnemonicGetString(result.mnemonic)},
                    {"hash", diagnostics::Hex(hash)},
                    {"decode_begin_rva", diagnostics::Hex(recipe.decode.code.begin - module.address)},
                    {"decode_end_rva", diagnostics::Hex(recipe.decode.code.end - module.address)},
                    {"receiver_vtable_unchanged", receiver_stable},
                    {"receiver_reread_win32", receiver_reread_error},
                    {"metadata_link_unchanged", link_stable},
                    {"metadata_link_reread_win32", link_reread_error}, {"data_complete", complete},
                    {"actor_role_verified", false}, {"selected_by_reader", false}});
        }
        diagnostics::Write("receiver_diagnostic_end",
            {{"role", role}, {"receiver", diagnostics::Hex(receiver)}, {"recipes_attempted", recipes},
                {"complete", recipes && native.metadata.size() <= recipes},
                {"reason",
                    native.metadata.size() <= recipes ? "bounded sample finished"
                                                      : "metadata recipe limit"}});
    } catch (...) {
        diagnostics::Write("receiver_diagnostic_failed",
            {{"role", role}, {"path_index", path}, {"teb", teb}, {"receiver", receiver},
                {"complete", false}});
    }
}

void Reader::ReportDiagnostics(bool layouts) const noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        const auto& state = *impl_;
        state.trace.Report();
        state.feature_trace.Report();
        const std::array paths{
            state.root_expression, state.camera_expression, state.manager_expression, state.array_expression};
        if (paths != state.reported_paths) {
            state.reported_paths = paths;
            if (paths[0] && *paths[0] < state.native.roots.size()) {
                ReportProgram(
                    "selected_root", *paths[0], state.native.roots[*paths[0]].code, state.module.address);
                ReportProgram("selected_context", *paths[0], state.native.contexts[*paths[0]].code,
                    state.module.address);
            }
            if (paths[1] && *paths[1] < state.native.cameras.size())
                ReportProgram(
                    "selected_camera", *paths[1], state.native.cameras[*paths[1]].code, state.module.address);
            if (paths[2] && *paths[2] < state.native.managers.size())
                ReportProgram("selected_manager", *paths[2], state.native.managers[*paths[2]].code,
                    state.module.address);
            if (paths[3] && *paths[3] < state.native.arrays.size())
                ReportProgram(
                    "selected_array", *paths[3], state.native.arrays[*paths[3]].code, state.module.address);
        }
        const auto reads = state.process.Statistics();
        diagnostics::Write("reader_summary",
            {{"status", state.message}, {"win32", state.last_error}, {"epoch", state.epoch},
                {"selected", state.selected.has_value()},
                {"entity_count", state.selected ? state.selected->count : 0u},
                {"cached_entities", state.cache.size()},
                {"root_index",
                    state.root_expression ? static_cast<std::int64_t>(*state.root_expression) : -1},
                {"manager_index",
                    state.manager_expression ? static_cast<std::int64_t>(*state.manager_expression) : -1},
                {"array_index",
                    state.array_expression ? static_cast<std::int64_t>(*state.array_expression) : -1},
                {"camera_index",
                    state.camera_expression ? static_cast<std::int64_t>(*state.camera_expression) : -1},
                {"metadata_selected", state.metadata.has_value()},
                {"metadata_table_field", state.metadata ? state.metadata->table_field : 0u},
                {"metadata_hash_field", state.metadata ? state.metadata->hash_field : 0u},
                {"diagnostic_root_receivers", state.diagnostic_receiver_counts[0]},
                {"diagnostic_manager_receivers", state.diagnostic_receiver_counts[1]},
                {"diagnostic_receiver_limit", 16u}, {"diagnostic_metadata_recipe_limit", 16u},
                {"tls_index", state.tls_index}, {"read_calls", reads.calls},
                {"read_bytes_requested", reads.requested}, {"read_bytes_transferred", reads.transferred},
                {"read_failures", reads.failures}, {"last_read_win32", reads.last_error},
                {"invalid_poses", state.invalid_poses}, {"ambiguous_bones", state.ambiguous_bones},
                {"local_player_present", state.local_player != 0}});
        for (const auto& [error, count] : reads.errors)
            if (count)
                diagnostics::Write("transport_error_count", {{"win32", error}, {"count", count}});
        if (!layouts)
            return;
        if (state.selected) {
            const auto& selected = *state.selected;
            diagnostics::Write("verified_environment",
                {{"teb", diagnostics::Hex(selected.teb)}, {"tls", diagnostics::Hex(selected.tls)},
                    {"parent", diagnostics::Hex(selected.parent)},
                    {"manager", diagnostics::Hex(selected.manager)},
                    {"array", diagnostics::Hex(selected.array)},
                    {"camera", diagnostics::Hex(selected.camera)}, {"count", selected.count}});
            if (Pointer(selected.camera)) {
                DWORD error{};
                if (const auto matrix = state.process.Read<skeleton::Matrix>(selected.camera + 0x2c0, &error))
                    diagnostics::Artifact("camera_matrix", 0, std::as_bytes(std::span(&*matrix, 1)));
                else
                    diagnostics::Write(
                        "diagnostic_structure_read_failed", {{"role", "camera matrix"}, {"win32", error}});
            }
        }
        unsigned examples{};
        for (const auto& [entity, cached] : state.cache) {
            if (!cached.animation_component || !cached.transform_component || examples++ >= 8)
                continue;
            diagnostics::Write("entity_layout",
                {{"sample", examples - 1}, {"entity", diagnostics::Hex(entity)},
                    {"component_list", diagnostics::Hex(cached.list)},
                    {"animation", diagnostics::Hex(cached.animation_component)},
                    {"transform", diagnostics::Hex(cached.transform_component)},
                    {"rig", diagnostics::Hex(cached.rig)}, {"rig_names", diagnostics::Hex(cached.names)},
                    {"vtable_rva",
                        cached.vtable >= state.module.address &&
                                cached.vtable - state.module.address < state.module.size
                            ? diagnostics::Hex(cached.vtable - state.module.address)
                            : "outside image"},
                    {"component_field", cached.component_offset}, {"component_count", cached.component_count},
                    {"animation_index", cached.animation_index}, {"transform_index", cached.transform_index},
                    {"rig_path", cached.rig_path ? static_cast<std::int64_t>(*cached.rig_path) : -1},
                    {"pose_path", cached.pose_path ? static_cast<std::int64_t>(*cached.pose_path) : -1},
                    {"pose_count", cached.pose_count}, {"bone_binding", cached.binding.has_value()},
                    {"bone_binding_ambiguous", cached.binding && cached.binding->ambiguous},
                    {"name_component_present", cached.username_component != 0}});
        }
        unsigned types{};
        for (const auto& [table, hash] : state.hashes) {
            if (types++ >= 32)
                break;
            const auto extent = state.extents.find(table);
            diagnostics::Write("observed_type",
                {{"hash", diagnostics::Hex(hash)},
                    {"vtable_rva",
                        table >= state.module.address && table - state.module.address < state.module.size
                            ? diagnostics::Hex(table - state.module.address)
                            : "outside image"},
                    {"extent", extent == state.extents.end() ? 0ull : extent->second}});
            if (state.metadata && Pointer(table)) {
                DWORD error{};
                const auto info = state.process.Read<Address>(table + state.metadata->table_field, &error);
                if (info && Pointer(*info)) {
                    const auto size = state.process.Read<Address>(*info + 0x24);
                    const auto low = state.process.Read<std::uint16_t>(*info + 0x40);
                    const auto high = state.process.Read<std::uint16_t>(*info + 0x42);
                    diagnostics::Write("type_relationship",
                        {{"vtable", diagnostics::Hex(table)}, {"metadata", diagnostics::Hex(*info)},
                            {"extent", size.value_or(0)},
                            {"subtype_lower", low ? static_cast<int>(*low) : -1},
                            {"subtype_upper", high ? static_cast<int>(*high) : -1},
                            {"interval_read_complete", low.has_value() && high.has_value()}});
                }
            }
        }
    } catch (...) {
    }
}
}
