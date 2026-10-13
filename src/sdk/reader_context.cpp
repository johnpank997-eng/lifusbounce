#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::Resolve(Address teb, Address tls) -> Environment {
    Environment e{teb, tls};
    std::optional<std::size_t> matched_root, matched_camera, matched_manager, matched_array;
    std::optional<locators::MetadataDescriptor> matched_metadata;
    for (std::size_t index = 0; index < native.roots.size(); ++index)
        try {
            if (root_expression && index != *root_expression)
                continue;
            cpu.Reset(teb);
            const auto& context = native.contexts[index];
            if (!trace.Run(cpu, context.code, "context_emulation_failed", index, module.address))
                continue;
            const auto context_value = cpu.Get(context.output);
            trace.Probe("thread context gate", index, teb, context_value, context_value == 0);
            if (context_value != 0) {
                trace.Count("context_unselected");
                continue;
            }
            const auto& expression = native.roots[index];
            cpu.Reset(teb);
            if (!trace.Run(cpu, expression.code, "root_emulation_failed", index, module.address))
                continue;
            const auto parent = cpu.Get(expression.output);
            trace.Probe("root receiver pointer", index, teb, parent, Pointer(parent));
            if (!Pointer(parent) || !Section(Q(parent))) {
                trace.Count("root_pointer_rejected");
                continue;
            }
            for (std::size_t candidate = 0; candidate < native.managers.size(); ++candidate)
                try {
                    if (manager_expression && candidate != *manager_expression)
                        continue;
                    const auto& path = native.managers[candidate];
                    cpu.Reset(teb);
                    cpu.Set(ZYDIS_REGISTER_RCX, parent);
                    if (!trace.Run(cpu, path.code, "manager_emulation_failed", candidate, module.address))
                        continue;
                    const auto manager = cpu.Get(path.output);
                    trace.Probe("manager receiver pointer", candidate, parent, manager, Pointer(manager));
                    if (!Pointer(manager) || !Section(Q(manager))) {
                        trace.Count("manager_pointer_rejected");
                        continue;
                    }
                    for (std::size_t recipe = 0; recipe < native.arrays.size(); ++recipe)
                        try {
                            if (array_expression && recipe != *array_expression)
                                continue;
                            const auto& extraction = native.arrays[recipe];
                            cpu.Reset(teb);
                            cpu.Set(extraction.input, manager);
                            if (!trace.Run(
                                    cpu, extraction.code, "array_emulation_failed", recipe, module.address))
                                continue;
                            const auto entries = cpu.Get(extraction.array);
                            const auto count = cpu.Get(extraction.count) & 0x3fffffffull;
                            trace.Probe("entity array bounds", recipe, entries, count,
                                Pointer(entries) && count && count <= 0x3000);
                            if (!Pointer(entries) || !count || count > 0x3000) {
                                trace.Count("entity_array_bounds_rejected");
                                continue;
                            }
                            bool typed = false;
                            for (const auto first :
                                Array<Address>(entries, std::min<std::uint64_t>(count, 16)))
                                try {
                                    if (Pointer(first) && Section(Q(first))) {
                                        typed = true;
                                        break;
                                    }
                                } catch (ReadFailure) {
                                }
                            if (!typed) {
                                trace.Count("entity_array_without_typed_entries");
                                continue;
                            }

                            if (!selected) {
                                const auto key = std::pair{entries, static_cast<std::uint32_t>(count)};
                                const auto found = selection_arrays.find(key);
                                if (found != selection_arrays.end())
                                    metadata = found->second;
                                else {
                                    Environment probe{teb, tls};
                                    probe.parent = parent;
                                    probe.manager = manager;
                                    probe.array = entries;
                                    probe.count = static_cast<std::uint32_t>(count);
                                    trace.Count("root_manager_array_probe");
                                    SelectMetadata(probe, {});
                                    selection_arrays.emplace(key, metadata);
                                }
                                if (!metadata) {
                                    trace.Count("entity_array_without_component_metadata");
                                    continue;
                                }
                                matched_metadata = metadata;
                            }
                            if (e.parent &&
                                (e.parent != parent || e.manager != manager || e.array != entries))
                                throw ReadFailure{ERROR_DUP_NAME};
                            e.parent = parent;
                            e.manager = manager;
                            e.array = entries;
                            e.count = static_cast<std::uint32_t>(count);
                            trace.Count("root_manager_array_verified");
                            matched_root = index;
                            matched_manager = candidate;
                            matched_array = recipe;
                        } catch (ReadFailure failure) {
                            trace.Error("array_path_rejected", failure.error);
                            if (failure.error == ERROR_DUP_NAME)
                                throw;
                        }
                } catch (ReadFailure failure) {
                    trace.Error("manager_path_rejected", failure.error);
                    if (failure.error == ERROR_DUP_NAME)
                        throw;
                }
        } catch (ReadFailure failure) {
            trace.Error("root_path_rejected", failure.error);
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    if (!e.parent) {
        if (root_expression || manager_expression || array_expression) {
            root_expression.reset();
            manager_expression.reset();
            array_expression.reset();
            return Resolve(teb, tls);
        }
        throw ReadFailure{ERROR_NOT_READY};
    }
    if (selected && (e.manager != selected->manager || e.array != selected->array))
        camera_expression.reset();
    for (std::size_t index = 0; index < native.cameras.size(); ++index)
        try {
            if (camera_expression && index != *camera_expression)
                continue;
            const auto& expression = native.cameras[index];
            cpu.Reset(teb);
            if (!trace.Run(cpu, expression.code, "camera_emulation_failed", index, module.address))
                continue;
            const auto parent = cpu.Get(expression.output);
            trace.Probe("camera receiver pointer", index, teb, parent, Pointer(parent));
            if (!Pointer(parent) || !Section(Q(parent))) {
                trace.Count("camera_parent_rejected");
                continue;
            }
            const auto camera = Q(parent + 0xf00);
            trace.Probe("camera object pointer", index, parent + 0xf00, camera, Pointer(camera));
            if (!Pointer(camera)) {
                trace.Count("camera_pointer_rejected");
                continue;
            }
            const auto view = Read<skeleton::Matrix>(camera + 0x2c0);
            if (!Projection(view)) {
                trace.Count("camera_matrix_rejected");
                continue;
            }
            if (e.camera && e.camera != camera)
                throw ReadFailure{ERROR_DUP_NAME};
            trace.Count("camera_verified");
            e.camera = camera;
            matched_camera = index;
        } catch (ReadFailure failure) {
            trace.Error("camera_path_rejected", failure.error);
            if (failure.error == ERROR_DUP_NAME)
                throw;
        }
    if (!e.camera) {
        if (camera_expression) {
            camera_expression.reset();
            return Resolve(teb, tls);
        }
        throw ReadFailure{ERROR_NOT_READY};
    }
    if (!selected)
        metadata = std::move(matched_metadata);
    root_expression = matched_root;
    camera_expression = matched_camera;
    manager_expression = matched_manager;
    array_expression = matched_array;
    return e;
}

auto Reader::Implementation::Select(std::stop_token stop) -> bool {
    message = "selecting the game thread environment";
    DWORD terr = ERROR_SUCCESS;
    const auto tlist = process.Threads(terr);
    trace.Count("selection_attempts");
    if (terr) {
        trace.Error("thread_enumeration_failed", terr);
        throw ReadFailure{terr};
    }
    selection_arrays.clear();
    std::optional<Environment> accepted;
    std::optional<locators::MetadataDescriptor> accepted_metadata;
    for (const auto& t : tlist) {
        if (stop.stop_requested())
            return false;
        try {
            trace.Count("threads_checked");
            const auto teb = static_cast<Address>(t.teb);
            if (!Pointer(teb) || Q(teb + 0x30) != teb) {
                trace.Count("thread_teb_rejected");
                continue;
            }
            const auto tls = Q(Q(teb + 0x58) + tls_index * 8ull);
            if (!Pointer(tls)) {
                trace.Count("thread_tls_rejected");
                continue;
            }
            const auto candidate = Resolve(teb, tls);
            if (accepted && !Equivalent(*accepted, candidate)) {
                trace.Count("thread_environments_disagree");
                message = "thread environments disagree";
                selected.reset();
                return false;
            }
            if (!accepted) {
                accepted = candidate;
                accepted_metadata = metadata;
            }
        } catch (ReadFailure failure) {
            trace.Error("thread_environment_rejected", failure.error);
        }
    }
    selected = accepted;
    metadata = std::move(accepted_metadata);
    hashes.clear();
    extents.clear();
    if (!accepted)
        message = "waiting for valid game roots";
    return accepted.has_value();
}

auto Reader::Implementation::SelectMetadata(const Environment& env, std::stop_token stop) -> bool {
    operator_name_path.reset();
    animation_operators.clear();
    weapon_paths.clear();
    weapon_names.clear();
    equipment_methods.clear();
    std::optional<locators::MetadataDescriptor> accepted;
    const auto entries = Array<Address>(env.array, env.count);
    for (const auto& candidate : native.metadata) {
        trace.Count("metadata_recipes_tested");
        metadata = candidate;
        hashes.clear();
        extents.clear();
        bool matched = false;
        for (const auto entity : entries) {
            if (stop.stop_requested()) {
                metadata.reset();
                return false;
            }
            try {
                const auto c = Discover(entity);
                if (c.animation_component && c.transform_component) {
                    matched = true;
                    break;
                }
            } catch (ReadFailure) {
            }
        }
        if (matched) {
            if (accepted) {
                metadata.reset();
                hashes.clear();
                extents.clear();
                throw ReadFailure{ERROR_DUP_NAME};
            }
            trace.Count("component_metadata_verified");
            accepted = candidate;
        }
    }
    metadata = std::move(accepted);
    hashes.clear();
    extents.clear();
    if (!metadata) {
        message = "waiting for verified component metadata";
        return false;
    }
    return true;
}
}
