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
            if (!cpu.Run(context.code).Complete() || cpu.Get(context.output) != 0)
                continue;
            const auto& expression = native.roots[index];
            cpu.Reset(teb);
            if (!cpu.Run(expression.code).Complete())
                continue;
            const auto parent = cpu.Get(expression.output);
            if (!Pointer(parent) || !Section(Q(parent)))
                continue;
            for (std::size_t candidate = 0; candidate < native.managers.size(); ++candidate)
                try {
                    if (manager_expression && candidate != *manager_expression)
                        continue;
                    const auto& path = native.managers[candidate];
                    cpu.Reset(teb);
                    cpu.Set(ZYDIS_REGISTER_RCX, parent);
                    if (!cpu.Run(path.code).Complete())
                        continue;
                    const auto manager = cpu.Get(path.output);
                    if (!Pointer(manager) || !Section(Q(manager)))
                        continue;
                    for (std::size_t recipe = 0; recipe < native.arrays.size(); ++recipe)
                        try {
                            if (array_expression && recipe != *array_expression)
                                continue;
                            const auto& extraction = native.arrays[recipe];
                            cpu.Reset(teb);
                            cpu.Set(extraction.input, manager);
                            if (!cpu.Run(extraction.code).Complete())
                                continue;
                            const auto entries = cpu.Get(extraction.array);
                            const auto count = cpu.Get(extraction.count) & 0x3fffffffull;
                            if (!Pointer(entries) || !count || count > 0x3000)
                                continue;
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
                            if (!typed)
                                continue;

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
                                    SelectMetadata(probe, {});
                                    selection_arrays.emplace(key, metadata);
                                }
                                if (!metadata)
                                    continue;
                                matched_metadata = metadata;
                            }
                            if (e.parent &&
                                (e.parent != parent || e.manager != manager || e.array != entries))
                                throw ReadFailure{ERROR_DUP_NAME};
                            e.parent = parent;
                            e.manager = manager;
                            e.array = entries;
                            e.count = static_cast<std::uint32_t>(count);
                            matched_root = index;
                            matched_manager = candidate;
                            matched_array = recipe;
                        } catch (ReadFailure failure) {
                            if (failure.error == ERROR_DUP_NAME)
                                throw;
                        }
                } catch (ReadFailure failure) {
                    if (failure.error == ERROR_DUP_NAME)
                        throw;
                }
        } catch (ReadFailure failure) {
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
            if (!cpu.Run(expression.code).Complete())
                continue;
            const auto parent = cpu.Get(expression.output);
            if (!Pointer(parent) || !Section(Q(parent)))
                continue;
            const auto camera = Q(parent + 0xf00);
            if (!Pointer(camera))
                continue;
            const auto view = Read<skeleton::Matrix>(camera + 0x2c0);
            if (!Projection(view))
                continue;
            if (e.camera && e.camera != camera)
                throw ReadFailure{ERROR_DUP_NAME};
            e.camera = camera;
            matched_camera = index;
        } catch (ReadFailure failure) {
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
    if (terr)
        throw ReadFailure{terr};
    selection_arrays.clear();
    std::optional<Environment> accepted;
    std::optional<locators::MetadataDescriptor> accepted_metadata;
    for (const auto& t : tlist) {
        if (stop.stop_requested())
            return false;
        try {
            const auto teb = static_cast<Address>(t.teb);
            if (!Pointer(teb) || Q(teb + 0x30) != teb)
                continue;
            const auto tls = Q(Q(teb + 0x58) + tls_index * 8ull);
            if (!Pointer(tls))
                continue;
            const auto candidate = Resolve(teb, tls);
            if (accepted && !Equivalent(*accepted, candidate)) {
                message = "thread environments disagree";
                selected.reset();
                return false;
            }
            if (!accepted) {
                accepted = candidate;
                accepted_metadata = metadata;
            }
        } catch (ReadFailure) {
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
