#include "sdk/reader_internal.hpp"
#include "core/diagnostics.hpp"

namespace base::sdk {
void Reader::ReportDiagnostics(bool layouts) const noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        const auto& state = *impl_;
        state.trace.Report();
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
