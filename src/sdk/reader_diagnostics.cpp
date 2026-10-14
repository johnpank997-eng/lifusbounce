#include "sdk/reader_internal.hpp"
#include "core/diagnostics.hpp"

namespace base::sdk {
std::optional<std::pair<std::uint64_t, std::uint64_t>> CameraDiagnosticReadBound(
    const Emulator::Program& code) noexcept {
    if (!code.linear)
        return std::nullopt;
    return std::pair{static_cast<std::uint64_t>(code.instructions.size()) * 2,
        static_cast<std::uint64_t>(code.instructions.size()) * 16};
}

namespace {
std::optional<unsigned> ReceiverRole(std::string_view role) {
    if (role == "root")
        return 0;
    if (role == "manager")
        return 1;
    if (role == "camera_parent")
        return 2;
    if (role == "camera_object")
        return 3;
    return std::nullopt;
}

unsigned ReceiverLimit(unsigned role) {
    return role >= 2 ? 8u : 16u;
}

unsigned MetadataRecipeLimit(unsigned role) {
    return role >= 2 ? 8u : 16u;
}

std::string_view OutcomeName(CameraPathOutcome outcome) {
    switch (outcome) {
    case CameraPathOutcome::emulation_failed:
        return "emulation_failed";
    case CameraPathOutcome::parent_not_pointer:
        return "parent_not_pointer";
    case CameraPathOutcome::parent_vtable_read_failed:
        return "parent_vtable_read_failed";
    case CameraPathOutcome::parent_vtable_outside_image:
        return "parent_vtable_outside_image";
    case CameraPathOutcome::object_slot_read_failed:
        return "object_slot_read_failed";
    case CameraPathOutcome::object_not_pointer:
        return "object_not_pointer";
    case CameraPathOutcome::matrix_read_failed:
        return "matrix_read_failed";
    case CameraPathOutcome::projection_rejected:
        return "projection_rejected";
    case CameraPathOutcome::camera_disagreed:
        return "camera_disagreed";
    case CameraPathOutcome::verified:
        return "verified";
    }
    return "unknown";
}

std::string_view ObjectClassification(Address camera, bool in_image) {
    if (!camera)
        return "null";
    if (!Pointer(camera))
        return camera <= 0x1000 ? "low_numeric" : "noncanonical";
    return in_image ? "module" : "heap_looking";
}
}

void Reader::Implementation::ReportCameraDiagnosticBudget(std::string_view category, std::string_view reason,
    std::uint64_t requested_calls, std::uint64_t requested_bytes) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        if (!camera_diagnostic_limits_reported.emplace(reason).second)
            return;
        const bool metadata_budget = category == "metadata";
        diagnostics::Write("camera_diagnostic_budget_exhausted",
            {{"category", category}, {"reason", reason}, {"requested_calls", requested_calls},
                {"requested_bytes", requested_bytes},
                {"calls_used", metadata_budget ? camera_metadata_read_calls : camera_sample_read_calls},
                {"bytes_used", metadata_budget ? camera_metadata_read_bytes : camera_sample_read_bytes},
                {"call_limit",
                    metadata_budget ? camera_metadata_read_call_limit : camera_sample_read_call_limit},
                {"byte_limit",
                    metadata_budget ? camera_metadata_read_byte_limit : camera_sample_read_byte_limit}});
    } catch (...) {
    }
}

void Reader::Implementation::ReportCameraDiagnosticLimit(
    std::string_view category, std::string_view reason, std::uint64_t used, std::uint64_t limit) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        if (!camera_diagnostic_limits_reported.emplace(reason).second)
            return;
        diagnostics::Write("camera_diagnostic_limit_reached",
            {{"category", category}, {"reason", reason}, {"used", used}, {"limit", limit}});
    } catch (...) {
    }
}

void Reader::Implementation::ReportCameraDiagnosticSkip(
    std::string_view category, std::string_view reason) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        if (!camera_diagnostic_limits_reported.emplace(reason).second)
            return;
        diagnostics::Write("camera_diagnostic_skipped", {{"category", category}, {"reason", reason}});
    } catch (...) {
    }
}

bool Reader::Implementation::ReserveCameraDiagnosticRead(
    std::string_view category, std::string_view stage, std::uint64_t calls, std::uint64_t bytes) noexcept {
    if (category == "metadata") {
        if (calls > camera_metadata_read_call_limit - camera_metadata_read_calls ||
            bytes > camera_metadata_read_byte_limit - camera_metadata_read_bytes) {
            ReportCameraDiagnosticBudget(category, stage, calls, bytes);
            return false;
        }
        camera_metadata_read_calls += calls;
        camera_metadata_read_bytes += bytes;
        return true;
    }
    if (calls > camera_sample_read_call_limit - camera_sample_read_calls ||
        bytes > camera_sample_read_byte_limit - camera_sample_read_bytes) {
        ReportCameraDiagnosticBudget(category, stage, calls, bytes);
        return false;
    }
    camera_sample_read_calls += calls;
    camera_sample_read_bytes += bytes;
    return true;
}

void Reader::Implementation::ReportReceiverDiagnostics(
    std::string_view role, std::size_t path, Address teb, Address receiver) noexcept {
    if (!diagnostics::Enabled() || !Pointer(receiver) || sizeof(Address) > 0x800000000000ull - receiver)
        return;
    try {
        const auto resolved_role = ReceiverRole(role);
        if (!resolved_role)
            return;
        const auto role_index = *resolved_role;
        const auto receiver_limit = ReceiverLimit(role_index);
        const auto recipe_limit = MetadataRecipeLimit(role_index);
        const bool camera_role = role_index >= 2;
        auto& receivers = diagnostic_receivers[role_index];
        auto& receiver_count = diagnostic_receiver_counts[role_index];
        if (std::find(receivers.begin(), receivers.begin() + receiver_count, receiver) !=
            receivers.begin() + receiver_count)
            return;
        if (receiver_count >= receiver_limit) {
            if (!diagnostic_receiver_limit_reported[role_index]) {
                diagnostic_receiver_limit_reported[role_index] = true;
                diagnostics::Write("receiver_diagnostic_limit",
                    {{"role", role}, {"path_index", path}, {"teb", diagnostics::Hex(teb)},
                        {"receiver", diagnostics::Hex(receiver)}, {"receiver_limit", receiver_limit},
                        {"metadata_recipe_limit", recipe_limit}, {"complete", false}});
                if (camera_role)
                    ReportCameraDiagnosticLimit("receivers",
                        role_index == 2 ? "camera_parent_receiver_limit" : "camera_object_receiver_limit",
                        receiver_count, receiver_limit);
            }
            return;
        }
        receivers[receiver_count++] = receiver;
        const auto read = [&]<class T>(Address at, DWORD* error, std::string_view stage) -> std::optional<T> {
            if (camera_role && !ReserveCameraDiagnosticRead("metadata", stage, 1, sizeof(T))) {
                if (error)
                    *error = ERROR_NOT_ENOUGH_QUOTA;
                return std::nullopt;
            }
            return process.Read<T>(at, error);
        };
        DWORD vtable_error{};
        const auto vtable = read.template operator()<Address>(receiver, &vtable_error, "receiver_vtable");
        const auto table_valid = vtable && Pointer(*vtable) && Section(*vtable);
        diagnostics::Write("receiver_diagnostic_begin",
            {{"role", role}, {"sample", receiver_count - 1}, {"path_index", path},
                {"teb", diagnostics::Hex(teb)}, {"receiver", diagnostics::Hex(receiver)},
                {"vtable", diagnostics::Hex(vtable.value_or(0))},
                {"vtable_read_complete", vtable.has_value()}, {"vtable_win32", vtable_error},
                {"vtable_in_image_section", table_valid}, {"metadata_recipes", native.metadata.size()},
                {"receiver_limit", receiver_limit}, {"metadata_recipe_limit", recipe_limit},
                {"selected_by_reader", false}});
        if (!table_valid) {
            diagnostics::Write("receiver_diagnostic_end",
                {{"role", role}, {"receiver", diagnostics::Hex(receiver)}, {"recipes_attempted", 0u},
                    {"complete", false}, {"reason", "vtable read or section check failed"}});
            return;
        }
        const auto recipes = std::min<std::size_t>(native.metadata.size(), recipe_limit);
        if (camera_role && native.metadata.size() > recipes)
            ReportCameraDiagnosticLimit("recipes",
                role_index == 2 ? "camera_parent_metadata_recipe_limit"
                                : "camera_object_metadata_recipe_limit",
                recipes, recipe_limit);
        Emulator diagnostic_cpu(process);
        for (std::size_t index = 0; index < recipes; ++index) {
            const auto& recipe = native.metadata[index];
            const auto link_address = *vtable + recipe.table_field;
            DWORD link_error = ERROR_INVALID_ADDRESS;
            std::optional<Address> info;
            if (Pointer(link_address) && Section(link_address) && Section(link_address + sizeof(Address) - 1))
                info = read.template operator()<Address>(link_address, &link_error, "metadata_link");
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
                    encoded_hash = read.template operator()<std::uint32_t>(
                        *info + recipe.hash_field, &hash_error, "metadata_hash");
                if (Section(*info + 0x24) && Section(*info + 0x2b))
                    extent =
                        read.template operator()<Address>(*info + 0x24, &extent_error, "metadata_extent");
                if (Section(*info + 0x40) && Section(*info + 0x41))
                    low = read.template operator()<std::uint16_t>(
                        *info + 0x40, &low_error, "metadata_interval_low");
                if (Section(*info + 0x42) && Section(*info + 0x43))
                    high = read.template operator()<std::uint16_t>(
                        *info + 0x42, &high_error, "metadata_interval_high");
                diagnostic_cpu.Reset(teb);
                diagnostic_cpu.Set(ZYDIS_REGISTER_RCX, receiver);
                const auto bound = camera_role ? CameraDiagnosticReadBound(recipe.decode.code)
                                               : std::optional(std::pair<std::uint64_t, std::uint64_t>{});
                bool decode_allowed = !camera_role;
                if (camera_role && !bound) {
                    result.status = EmulationStatus::unsupported;
                    ReportCameraDiagnosticSkip("decoder", "nonlinear_metadata_decode");
                } else if (camera_role &&
                    ReserveCameraDiagnosticRead("metadata", "metadata_decode", bound->first, bound->second)) {
                    decode_allowed = true;
                } else if (camera_role) {
                    result.status = EmulationStatus::budget_exhausted;
                }
                if (decode_allowed) {
                    decode_attempted = true;
                    const auto decode_stage = role_index == 2 ? "camera_parent_metadata_decode"
                        : role_index == 3                     ? "camera_object_metadata_decode"
                                                              : "receiver_metadata_decode";
                    result = trace.Execute(
                        diagnostic_cpu, recipe.decode.code, decode_stage, index, module.address);
                    if (result.Complete())
                        hash = static_cast<std::uint32_t>(diagnostic_cpu.Get(recipe.decode.output));
                }
            }
            DWORD receiver_reread_error{}, link_reread_error = ERROR_INVALID_ADDRESS;
            const auto receiver_reread =
                read.template operator()<Address>(receiver, &receiver_reread_error, "receiver_reread");
            std::optional<Address> link_reread;
            if (Pointer(link_address) && Section(link_address) && Section(link_address + sizeof(Address) - 1))
                link_reread = read.template operator()<Address>(
                    link_address, &link_reread_error, "metadata_link_reread");
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

void Reader::Implementation::ReportCameraDiagnostics(const CameraAttemptEvidence& attempt) noexcept {
    if (!diagnostics::Enabled())
        return;
    try {
        if (!camera_screen_state_epoch || *camera_screen_state_epoch != epoch) {
            camera_screen_state_epoch = epoch;
            diagnostics::Write(
                "camera_screen_state", {{"state", "unknown"}, {"source", "not supplied"}, {"epoch", epoch}});
        }
        const CameraAttemptKey attempt_key{epoch, attempt.teb, attempt.root, attempt.manager, attempt.array,
            attempt.root_path, attempt.manager_path, attempt.array_path, attempt.path, attempt.outcome,
            attempt.parent, attempt.parent_vtable, attempt.parent_vtable_read_complete, attempt.camera,
            attempt.object_slot_read_complete, attempt.failing_address, attempt.matrix.has_value(),
            attempt.error};
        if (!camera_attempts.contains(attempt_key)) {
            if (camera_attempts.size() < camera_attempt_limit) {
                camera_attempts.insert(attempt_key);
                diagnostics::Write("camera_path_attempt",
                    {{"path_index", attempt.path}, {"outcome", OutcomeName(attempt.outcome)},
                        {"win32", attempt.error}, {"epoch", epoch}, {"teb", diagnostics::Hex(attempt.teb)},
                        {"root_path", attempt.root_path}, {"manager_path", attempt.manager_path},
                        {"array_path", attempt.array_path}, {"root", diagnostics::Hex(attempt.root)},
                        {"manager", diagnostics::Hex(attempt.manager)},
                        {"array", diagnostics::Hex(attempt.array)},
                        {"parent", diagnostics::Hex(attempt.parent)},
                        {"parent_vtable", diagnostics::Hex(attempt.parent_vtable)},
                        {"parent_vtable_read_complete", attempt.parent_vtable_read_complete},
                        {"camera", diagnostics::Hex(attempt.camera)},
                        {"object_slot_read_complete", attempt.object_slot_read_complete},
                        {"failing_address", diagnostics::Hex(attempt.failing_address)},
                        {"matrix_read_complete", attempt.matrix.has_value()}, {"screen_state", "unknown"}});
            } else if (!camera_attempt_limit_reported) {
                camera_attempt_limit_reported = true;
                ReportCameraDiagnosticLimit(
                    "records", "camera_path_attempt_limit", camera_attempts.size(), camera_attempt_limit);
            }
        }
        if (attempt.parent_vtable_read_complete) {
            const auto key = attempt.parent;
            const auto end = camera_parent_samples.begin() + camera_parent_sample_count;
            if (std::find(camera_parent_samples.begin(), end, key) == end) {
                if (camera_parent_sample_count >= camera_parent_samples.size())
                    ReportCameraDiagnosticLimit("identities", "camera_parent_sample_limit",
                        camera_parent_sample_count, camera_parent_samples.size());
                else {
                    camera_parent_samples[camera_parent_sample_count++] = key;
                    DWORD error = ERROR_NOT_ENOUGH_QUOTA;
                    std::optional<Address> reread;
                    if (ReserveCameraDiagnosticRead("samples", "camera_parent_sample", 1, sizeof(Address)))
                        reread = process.Read<Address>(attempt.parent, &error);
                    diagnostics::Write("camera_parent_sample",
                        {{"path_index", attempt.path}, {"epoch", epoch},
                            {"parent", diagnostics::Hex(attempt.parent)},
                            {"vtable", diagnostics::Hex(attempt.parent_vtable)},
                            {"vtable_in_image_section", Section(attempt.parent_vtable)},
                            {"vtable_rva",
                                Section(attempt.parent_vtable)
                                    ? diagnostics::Hex(attempt.parent_vtable - module.address)
                                    : "outside image"},
                            {"reread", diagnostics::Hex(reread.value_or(0))},
                            {"reread_complete", reread.has_value()}, {"reread_win32", error},
                            {"unchanged", reread && *reread == attempt.parent_vtable},
                            {"equals_root", attempt.parent == attempt.root},
                            {"equals_manager", attempt.parent == attempt.manager},
                            {"equals_array", attempt.parent == attempt.array}});
                }
            }
            ReportReceiverDiagnostics("camera_parent", attempt.path, attempt.teb, attempt.parent);
        }
        if (attempt.object_slot_read_complete) {
            const auto key = std::pair{attempt.parent, attempt.camera};
            const auto end = camera_object_samples.begin() + camera_object_sample_count;
            if (std::find(camera_object_samples.begin(), end, key) == end) {
                if (camera_object_sample_count >= camera_object_samples.size())
                    ReportCameraDiagnosticLimit("identities", "camera_object_sample_limit",
                        camera_object_sample_count, camera_object_samples.size());
                else {
                    camera_object_samples[camera_object_sample_count++] = key;
                    const auto pointer = Pointer(attempt.camera);
                    const auto calls = pointer ? 2u : 1u;
                    const auto bytes = calls * sizeof(Address);
                    DWORD slot_error = ERROR_NOT_ENOUGH_QUOTA, vtable_error = ERROR_NOT_ENOUGH_QUOTA;
                    std::optional<Address> slot_reread, vtable;
                    if (ReserveCameraDiagnosticRead("samples", "camera_object_sample", calls, bytes)) {
                        slot_reread = process.Read<Address>(attempt.parent + 0xf00, &slot_error);
                        if (pointer)
                            vtable = process.Read<Address>(attempt.camera, &vtable_error);
                    }
                    diagnostics::Write("camera_object_slot_sample",
                        {{"path_index", attempt.path}, {"epoch", epoch},
                            {"parent", diagnostics::Hex(attempt.parent)},
                            {"slot_address", diagnostics::Hex(attempt.parent + 0xf00)},
                            {"camera", diagnostics::Hex(attempt.camera)},
                            {"classification", ObjectClassification(attempt.camera, Section(attempt.camera))},
                            {"reread", diagnostics::Hex(slot_reread.value_or(0))},
                            {"reread_complete", slot_reread.has_value()}, {"reread_win32", slot_error},
                            {"unchanged", slot_reread && *slot_reread == attempt.camera}});
                    diagnostics::Write("camera_object_sample",
                        {{"path_index", attempt.path}, {"epoch", epoch},
                            {"camera", diagnostics::Hex(attempt.camera)},
                            {"vtable", diagnostics::Hex(vtable.value_or(0))},
                            {"vtable_read_complete", vtable.has_value()}, {"vtable_win32", vtable_error},
                            {"vtable_in_image_section", vtable && Section(*vtable)},
                            {"vtable_rva",
                                vtable && Section(*vtable) ? diagnostics::Hex(*vtable - module.address)
                                                           : "outside image"}});
                }
            }
            if (Pointer(attempt.camera))
                ReportReceiverDiagnostics("camera_object", attempt.path, attempt.teb, attempt.camera);
        }
        if (attempt.matrix) {
            std::array<std::uint32_t, 16> words{};
            std::memcpy(words.data(), attempt.matrix->data(), sizeof(words));
            const auto key = std::pair{attempt.camera, words};
            const auto end = camera_matrix_samples.begin() + camera_matrix_sample_count;
            if (std::find(camera_matrix_samples.begin(), end, key) == end) {
                if (camera_matrix_sample_count >= camera_matrix_samples.size())
                    ReportCameraDiagnosticLimit("identities", "camera_matrix_sample_limit",
                        camera_matrix_sample_count, camera_matrix_samples.size());
                else {
                    camera_matrix_samples[camera_matrix_sample_count++] = key;
                    DWORD error = ERROR_NOT_ENOUGH_QUOTA;
                    std::optional<skeleton::Matrix> reread;
                    if (ReserveCameraDiagnosticRead(
                            "samples", "camera_matrix_sample", 1, sizeof(skeleton::Matrix)))
                        reread = process.Read<skeleton::Matrix>(attempt.camera + 0x2c0, &error);
                    const auto current = InspectProjection(*attempt.matrix);
                    const auto transposed = InspectProjection(*attempt.matrix, true);
                    const auto bytes = std::as_bytes(std::span(&*attempt.matrix, 1));
                    const bool reread_unchanged =
                        reread && std::memcmp(&*reread, &*attempt.matrix, sizeof(skeleton::Matrix)) == 0;
                    diagnostics::Write("camera_matrix_sample",
                        {{"path_index", attempt.path}, {"epoch", epoch},
                            {"camera", diagnostics::Hex(attempt.camera)},
                            {"matrix_address", diagnostics::Hex(attempt.camera + 0x2c0)},
                            {"sha256", diagnostics::Sha256(bytes)}, {"word00", diagnostics::Hex(words[0])},
                            {"word01", diagnostics::Hex(words[1])}, {"word02", diagnostics::Hex(words[2])},
                            {"word03", diagnostics::Hex(words[3])}, {"word04", diagnostics::Hex(words[4])},
                            {"word05", diagnostics::Hex(words[5])}, {"word06", diagnostics::Hex(words[6])},
                            {"word07", diagnostics::Hex(words[7])}, {"word08", diagnostics::Hex(words[8])},
                            {"word09", diagnostics::Hex(words[9])}, {"word10", diagnostics::Hex(words[10])},
                            {"word11", diagnostics::Hex(words[11])}, {"word12", diagnostics::Hex(words[12])},
                            {"word13", diagnostics::Hex(words[13])}, {"word14", diagnostics::Hex(words[14])},
                            {"word15", diagnostics::Hex(words[15])},
                            {"current_rejection_mask", diagnostics::Hex(current.rejections)},
                            {"current_accepted", current.Accepted()},
                            {"current_axis0_length", current.lengths[0]},
                            {"current_axis1_length", current.lengths[1]},
                            {"current_axis2_length", current.lengths[2]},
                            {"current_axis3_length", current.lengths[3]}, {"current_dot01", current.dot01},
                            {"current_dot03", current.dot03}, {"current_dot13", current.dot13},
                            {"current_dot23", current.dot23},
                            {"transposed_rejection_mask", diagnostics::Hex(transposed.rejections)},
                            {"transposed_accepted", transposed.Accepted()},
                            {"transposed_axis0_length", transposed.lengths[0]},
                            {"transposed_axis1_length", transposed.lengths[1]},
                            {"transposed_axis2_length", transposed.lengths[2]},
                            {"transposed_axis3_length", transposed.lengths[3]},
                            {"transposed_dot01", transposed.dot01}, {"transposed_dot03", transposed.dot03},
                            {"transposed_dot13", transposed.dot13}, {"transposed_dot23", transposed.dot23},
                            {"reread_complete", reread.has_value()}, {"reread_win32", error},
                            {"reread_unchanged", reread_unchanged},
                            {"reread_sha256",
                                reread ? diagnostics::Sha256(std::as_bytes(std::span(&*reread, 1))) : ""}});
                }
            }
        }
    } catch (...) {
        diagnostics::Write("camera_diagnostic_failed",
            {{"path_index", attempt.path}, {"outcome", OutcomeName(attempt.outcome)}});
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
                {"diagnostic_camera_parent_receivers", state.diagnostic_receiver_counts[2]},
                {"diagnostic_camera_object_receivers", state.diagnostic_receiver_counts[3]},
                {"diagnostic_receiver_limit", 16u}, {"diagnostic_metadata_recipe_limit", 16u},
                {"diagnostic_camera_receiver_limit", 8u}, {"diagnostic_camera_metadata_recipe_limit", 8u},
                {"camera_sample_read_calls", state.camera_sample_read_calls},
                {"camera_sample_read_bytes", state.camera_sample_read_bytes},
                {"camera_sample_read_call_limit", state.camera_sample_read_call_limit},
                {"camera_sample_read_byte_limit", state.camera_sample_read_byte_limit},
                {"camera_metadata_read_calls", state.camera_metadata_read_calls},
                {"camera_metadata_read_bytes", state.camera_metadata_read_bytes},
                {"camera_metadata_read_call_limit", state.camera_metadata_read_call_limit},
                {"camera_metadata_read_byte_limit", state.camera_metadata_read_byte_limit},
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
