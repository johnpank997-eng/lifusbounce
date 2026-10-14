#include "sdk/feature_diagnostics.hpp"
#include "core/diagnostics.hpp"
#include <algorithm>
#include <limits>

namespace base::sdk {
namespace {
constexpr std::array FeatureNames{"name", "health", "operator", "team", "weapon", "defuser"};
constexpr std::array StageNames{"discovery", "component", "owner", "profile", "header", "text", "decode",
    "value", "instance", "definition", "reference", "animation layout", "animation modules", "checksum",
    "mapping", "affiliation", "resource", "codec", "flag", "snapshot"};
constexpr std::array StatusNames{"ready", "cached", "missing path", "ambiguous path", "missing component",
    "uninitialized", "emulation failed", "read failed", "type rejected", "extent rejected", "invalid layout",
    "invalid value", "state changed", "mapping missing", "unavailable"};
constexpr std::array MetadataStages{"name_receiver_metadata", "health_receiver_metadata",
    "operator_receiver_metadata", "team_receiver_metadata", "weapon_receiver_metadata",
    "defuser_receiver_metadata"};

bool UserRange(std::uint64_t address, std::uint64_t size) {
    return address >= 0x10000 && address < 0x800000000000ull && size && size <= 0x800000000000ull - address;
}

bool ImageRange(std::span<const std::pair<std::uint64_t, std::uint64_t>> sections, std::uint64_t address,
    std::uint64_t size) {
    return UserRange(address, size) &&
        std::any_of(sections.begin(), sections.end(), [&](const auto& section) {
            return address >= section.first && address < section.second && size <= section.second - address;
        });
}

void Increment(std::uint64_t& value) {
    if (value != std::numeric_limits<std::uint64_t>::max())
        ++value;
}
}

void FeatureDiagnostics::Record(
    Feature feature, FeatureStage stage, FeatureStatus status, const FeatureEvidence& evidence) noexcept {
    if (!diagnostics::Enabled())
        return;
    const auto index = static_cast<unsigned>(feature), at = static_cast<unsigned>(stage),
               reason = static_cast<unsigned>(status);
    if (index >= Features || at >= Stages || reason >= Statuses)
        return;
    Increment(counts_[index][at][reason]);
    const Example key{stage, status, evidence};
    auto& values = examples_[index];
    auto& count = example_counts_[index];
    if (std::find(values.begin(), values.begin() + count, key) != values.begin() + count)
        return;
    const auto observation_class =
        status == FeatureStatus::ready || status == FeatureStatus::cached ? 0u : 1u;
    const auto class_limit = observation_class ? FailureExampleLimit : SuccessExampleLimit;
    const auto snapshot_unavailable = stage == FeatureStage::snapshot && status == FeatureStatus::unavailable;
    if (snapshot_unavailable && snapshot_unavailable_examples_[index] >= SnapshotUnavailableExampleLimit) {
        Increment(discarded_examples_[index]);
        Increment(discarded_snapshot_unavailable_[index]);
        if (!snapshot_limit_reported_[index]) {
            snapshot_limit_reported_[index] = true;
            diagnostics::Write("feature_snapshot_example_limit",
                {{"feature", FeatureNames[index]}, {"limit", SnapshotUnavailableExampleLimit},
                    {"failure_example_limit", FailureExampleLimit}, {"complete", false}});
        }
        return;
    }
    if (count >= values.size() || example_classes_[index][observation_class] >= class_limit) {
        Increment(discarded_examples_[index]);
        if (!example_limit_reported_[index][observation_class]) {
            example_limit_reported_[index][observation_class] = true;
            diagnostics::Write("feature_example_limit",
                {{"feature", FeatureNames[index]}, {"limit", ExampleLimit},
                    {"observation_class", observation_class ? "failure" : "success"},
                    {"class_limit", class_limit}, {"complete", false}});
        }
        return;
    }
    values[count++] = key;
    ++example_classes_[index][observation_class];
    if (snapshot_unavailable)
        ++snapshot_unavailable_examples_[index];
    try {
        diagnostics::Write("feature_status",
            {{"feature", FeatureNames[index]}, {"stage", StageNames[at]}, {"status", StatusNames[reason]},
                {"path_index", evidence.path}, {"entity", diagnostics::Hex(evidence.entity)},
                {"receiver", diagnostics::Hex(evidence.receiver)},
                {"parent", diagnostics::Hex(evidence.parent)},
                {"address", diagnostics::Hex(evidence.address)}, {"field", evidence.field},
                {"extent", evidence.extent}, {"value", diagnostics::Hex(evidence.value)},
                {"other", diagnostics::Hex(evidence.other)},
                {"expected", diagnostics::Hex(evidence.expected)},
                {"observed", diagnostics::Hex(evidence.observed)}, {"win32", evidence.win32},
                {"class_examples_remaining", class_limit - example_classes_[index][observation_class]},
                {"evidence_selected_by_reader", false}});
    } catch (...) {
    }
}

void FeatureDiagnostics::BeginCapture() noexcept {
    if (diagnostics::Enabled())
        receiver_deadline_ =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(ReceiverBudgetMilliseconds);
}

void FeatureDiagnostics::Receiver(const Memory& process, const ModuleInfo& module,
    std::span<const std::pair<std::uint64_t, std::uint64_t>> sections,
    std::span<const locators::MetadataDescriptor> metadata, Feature feature, FeatureStage stage,
    std::size_t path, std::uint64_t teb, std::uint64_t entity, std::uint64_t receiver) noexcept {
    if (!diagnostics::Enabled())
        return;
    const auto index = static_cast<unsigned>(feature), at = static_cast<unsigned>(stage);
    if (index >= Features || at >= Stages || !UserRange(receiver, sizeof(std::uint64_t)))
        return;
    const ReceiverKey key{stage, path, entity, receiver};
    auto& values = receivers_[index];
    auto& count = receiver_counts_[index];
    const auto found = std::find(values.begin(), values.begin() + count, key);
    const auto now = std::chrono::steady_clock::now();
    if (found != values.begin() + count && now < receiver_retry_[index][found - values.begin()])
        return;
    if (receiver_deadline_ == std::chrono::steady_clock::time_point{})
        BeginCapture();
    if (now >= receiver_deadline_) {
        Increment(receiver_budget_skips_[index]);
        return;
    }
    if ((found == values.begin() + count && count >= values.size()) ||
        receiver_samples_[index] >= ReceiverSampleLimit) {
        Increment(discarded_receivers_[index]);
        if (!receiver_limit_reported_[index]) {
            receiver_limit_reported_[index] = true;
            diagnostics::Write("feature_receiver_limit",
                {{"feature", FeatureNames[index]}, {"receiver_limit", ReceiverLimit},
                    {"receiver_sample_limit", ReceiverSampleLimit}, {"metadata_recipe_limit", MetadataLimit},
                    {"reason",
                        receiver_samples_[index] >= ReceiverSampleLimit ? "receiver sample limit"
                                                                        : "receiver identity limit"},
                    {"complete", false}});
        }
        return;
    }
    const auto identity = static_cast<std::size_t>(found - values.begin());
    const auto resample = found != values.begin() + count;
    const auto elapsed = resample
        ? std::chrono::duration_cast<std::chrono::milliseconds>(now - receiver_at_[index][identity]).count()
        : 0;
    if (found == values.begin() + count)
        values[count++] = key;
    receiver_retry_[index][identity] = now + std::chrono::seconds(ReceiverRetrySeconds);
    receiver_at_[index][identity] = now;
    ++receiver_samples_[index];
    try {
        const auto target_limit = feature == Feature::operator_id ? OperatorVtableLimit
            : feature == Feature::weapon                          ? WeaponVtableLimit
                                                                  : VtableLimit;
        bool budget_clipped{};
        const auto remaining = [&] {
            if (std::chrono::steady_clock::now() < receiver_deadline_)
                return true;
            budget_clipped = true;
            return false;
        };
        const auto read = [&]<class T>(std::uint64_t address, DWORD& error) -> std::optional<T> {
            if (!remaining()) {
                error = ERROR_TIMEOUT;
                return std::nullopt;
            }
            return process.Read<T>(address, &error);
        };
        DWORD table_error{};
        const auto table = read.operator()<std::uint64_t>(receiver, table_error);
        const auto table_in_module = table && *table >= module.address &&
            *table - module.address < module.size &&
            sizeof(std::uint64_t) <= module.size - (*table - module.address);
        const auto table_in_section = table && ImageRange(sections, *table, sizeof(std::uint64_t));
        const auto valid = table_in_module && table_in_section;
        diagnostics::Write("feature_receiver_begin",
            {{"feature", FeatureNames[index]}, {"stage", StageNames[at]}, {"path_index", path},
                {"entity", diagnostics::Hex(entity)}, {"receiver", diagnostics::Hex(receiver)},
                {"teb", diagnostics::Hex(teb)}, {"vtable", diagnostics::Hex(table.value_or(0))},
                {"vtable_read_complete", table.has_value()}, {"vtable_win32", table_error},
                {"vtable_in_image_section", table_in_section}, {"vtable_in_module", table_in_module},
                {"metadata_recipes", metadata.size()}, {"receiver_limit", ReceiverLimit},
                {"metadata_recipe_limit", MetadataLimit}, {"receiver_sample", receiver_samples_[index] - 1},
                {"receiver_sample_limit", ReceiverSampleLimit},
                {"receiver_retry_seconds", ReceiverRetrySeconds}, {"vtable_target_limit", target_limit},
                {"identity_resample", resample}, {"elapsed_since_previous_sample_ms", elapsed},
                {"receiver_budget_ms", ReceiverBudgetMilliseconds}, {"budget_is_soft", true},
                {"selected_by_reader", false}});
        if (!valid) {
            diagnostics::Write("feature_receiver_end",
                {{"feature", FeatureNames[index]}, {"receiver", diagnostics::Hex(receiver)},
                    {"complete", false}, {"reason", "vtable read or section check failed"},
                    {"receiver_budget_ms", ReceiverBudgetMilliseconds}, {"budget_is_soft", true},
                    {"receiver_budget_clipped", budget_clipped},
                    {"sample_elapsed_ms",
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - now)
                            .count()}});
            return;
        }
        unsigned targets = target_limit;
        while (targets && !ImageRange(sections, *table, targets * sizeof(std::uint64_t)))
            --targets;
        std::array<std::uint64_t, OperatorVtableLimit> methods{};
        ReadResult method_read{0, ERROR_TIMEOUT};
        if (targets && remaining())
            method_read =
                process.ReadBytes(*table, std::as_writable_bytes(std::span(methods).first(targets)));
        const auto retained_targets =
            std::min<std::size_t>(targets, method_read.transferred / sizeof(std::uint64_t));
        const auto method_bytes = std::as_bytes(std::span(methods).first(retained_targets));
        const auto method_hash = diagnostics::Sha256(method_bytes);
        const auto method_rva = *table - module.address;
        const auto method_key =
            std::string("feature_receiver_vtable:") + diagnostics::Hex(method_rva) + ":" + method_hash;
        const auto method_artifact = !method_bytes.empty() &&
            diagnostics::Artifact("feature_receiver_vtable", method_rva, method_bytes, {}, method_hash);
        diagnostics::Write("feature_receiver_methods",
            {{"feature", FeatureNames[index]}, {"stage", StageNames[at]}, {"path_index", path},
                {"entity", diagnostics::Hex(entity)}, {"receiver", diagnostics::Hex(receiver)},
                {"vtable", diagnostics::Hex(*table)}, {"target_limit", target_limit},
                {"targets_attempted", targets}, {"targets_retained", retained_targets},
                {"record_stride", sizeof(std::uint64_t)}, {"transferred", method_read.transferred},
                {"win32", method_read.error},
                {"read_complete",
                    method_read.Complete() && method_read.transferred == targets * sizeof(std::uint64_t)},
                {"artifact", method_key}, {"artifact_complete", method_artifact}, {"full_vtable", false}});
        const auto recipes = std::min<std::size_t>(metadata.size(), MetadataLimit);
        Emulator diagnostic_cpu(process);
        bool all_complete = recipes != 0 && method_artifact && method_read.Complete() &&
            method_read.transferred == targets * sizeof(std::uint64_t);
        std::size_t attempted{};
        for (std::size_t recipe_index = 0; recipe_index < recipes; ++recipe_index) {
            if (!remaining())
                break;
            ++attempted;
            const auto& recipe = metadata[recipe_index];
            const auto link_address = *table + recipe.table_field;
            DWORD link_error = ERROR_INVALID_ADDRESS;
            std::optional<std::uint64_t> info;
            if (ImageRange(sections, link_address, sizeof(std::uint64_t)))
                info = read.operator()<std::uint64_t>(link_address, link_error);
            const auto info_valid = info && ImageRange(sections, *info, 1);
            const auto image_read = [&]<class T>(std::uint64_t address, DWORD& error) -> std::optional<T> {
                error = ERROR_INVALID_ADDRESS;
                return ImageRange(sections, address, sizeof(T)) ? read.operator()<T>(address, error)
                                                                : std::nullopt;
            };
            DWORD hash_error = ERROR_INVALID_ADDRESS, extent_error = ERROR_INVALID_ADDRESS,
                  interval_error = ERROR_INVALID_ADDRESS;
            std::optional<std::uint32_t> encoded;
            std::optional<std::uint64_t> extent;
            std::optional<std::array<std::uint16_t, 2>> interval;
            EmulationResult result{EmulationStatus::read_failed};
            bool decode_attempted{};
            std::uint32_t decoded{};
            if (info_valid) {
                encoded = image_read.operator()<std::uint32_t>(*info + recipe.hash_field, hash_error);
                extent = image_read.operator()<std::uint64_t>(*info + 0x24, extent_error);
                interval = image_read.operator()<std::array<std::uint16_t, 2>>(*info + 0x40, interval_error);
                diagnostic_cpu.Reset(teb);
                diagnostic_cpu.Set(ZYDIS_REGISTER_RCX, receiver);
                if (remaining()) {
                    decode_attempted = true;
                    result = metadata_trace_.Execute(diagnostic_cpu, recipe.decode.code,
                        MetadataStages[index], recipe_index, module.address);
                }
                if (result.Complete())
                    decoded = static_cast<std::uint32_t>(diagnostic_cpu.Get(recipe.decode.output));
            }
            DWORD receiver_error{},
                link_again_error = ERROR_INVALID_ADDRESS, hash_again_error = ERROR_INVALID_ADDRESS,
                extent_again_error = ERROR_INVALID_ADDRESS, interval_again_error = ERROR_INVALID_ADDRESS;
            const auto table_again = read.operator()<std::uint64_t>(receiver, receiver_error);
            const auto info_again = image_read.operator()<std::uint64_t>(link_address, link_again_error);
            std::optional<std::uint32_t> encoded_again;
            std::optional<std::uint64_t> extent_again;
            std::optional<std::array<std::uint16_t, 2>> interval_again;
            if (info_valid) {
                encoded_again =
                    image_read.operator()<std::uint32_t>(*info + recipe.hash_field, hash_again_error);
                extent_again = image_read.operator()<std::uint64_t>(*info + 0x24, extent_again_error);
                interval_again =
                    image_read.operator()<std::array<std::uint16_t, 2>>(*info + 0x40, interval_again_error);
            }
            const auto receiver_stable = table_again && *table_again == *table;
            const auto link_stable = info && info_again && *info_again == *info;
            const auto metadata_stable = encoded && extent && interval && encoded_again == encoded &&
                extent_again == extent && interval_again == interval;
            const auto complete = info_valid && encoded && extent && interval && result.Complete() &&
                receiver_stable && link_stable && metadata_stable;
            all_complete = all_complete && complete;
            diagnostics::Write("feature_receiver_metadata",
                {{"feature", FeatureNames[index]}, {"stage", StageNames[at]}, {"path_index", path},
                    {"entity", diagnostics::Hex(entity)}, {"receiver", diagnostics::Hex(receiver)},
                    {"teb", diagnostics::Hex(teb)}, {"recipe_index", recipe_index},
                    {"vtable", diagnostics::Hex(*table)}, {"table_field", recipe.table_field},
                    {"hash_field", recipe.hash_field}, {"link_address", diagnostics::Hex(link_address)},
                    {"metadata", diagnostics::Hex(info.value_or(0))},
                    {"link_read_complete", info.has_value()}, {"link_win32", link_error},
                    {"metadata_in_image_section", info_valid},
                    {"encoded_hash", diagnostics::Hex(encoded.value_or(0))},
                    {"encoded_hash_read_complete", encoded.has_value()}, {"encoded_hash_win32", hash_error},
                    {"extent", extent.value_or(0)}, {"extent_read_complete", extent.has_value()},
                    {"extent_win32", extent_error},
                    {"subtype_lower", interval ? static_cast<int>((*interval)[0]) : -1},
                    {"subtype_upper", interval ? static_cast<int>((*interval)[1]) : -1},
                    {"interval_read_complete", interval.has_value()}, {"interval_win32", interval_error},
                    {"decode_attempted", decode_attempted}, {"decode_complete", result.Complete()},
                    {"decode_status", static_cast<unsigned>(result.status)}, {"decode_steps", result.steps},
                    {"decode_stop_rva",
                        result.address >= module.address ? diagnostics::Hex(result.address - module.address)
                                                         : "outside image"},
                    {"hash", diagnostics::Hex(decoded)}, {"receiver_vtable_unchanged", receiver_stable},
                    {"receiver_reread_win32", receiver_error}, {"metadata_link_unchanged", link_stable},
                    {"metadata_link_reread_win32", link_again_error},
                    {"metadata_values_unchanged", metadata_stable}, {"hash_reread_win32", hash_again_error},
                    {"extent_reread_win32", extent_again_error},
                    {"interval_reread_win32", interval_again_error}, {"data_complete", complete},
                    {"receiver_budget_clipped", budget_clipped}, {"actor_role_verified", false},
                    {"selected_by_reader", false}});
        }
        diagnostics::Write("feature_receiver_end",
            {{"feature", FeatureNames[index]}, {"receiver", diagnostics::Hex(receiver)},
                {"recipes_attempted", attempted}, {"metadata_recipes_clipped", metadata.size() > attempted},
                {"vtable_targets_attempted", targets}, {"vtable_targets_clipped", true},
                {"bounded_data_complete", all_complete && !budget_clipped && attempted == recipes},
                {"receiver_budget_ms", ReceiverBudgetMilliseconds}, {"budget_is_soft", true},
                {"receiver_budget_clipped", budget_clipped},
                {"sample_elapsed_ms",
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - now)
                        .count()},
                {"complete", all_complete && !budget_clipped && metadata.size() <= attempted}});
    } catch (...) {
        diagnostics::Write("feature_receiver_failed",
            {{"feature", FeatureNames[index]}, {"stage", StageNames[at]}, {"path_index", path},
                {"receiver", receiver}, {"complete", false}});
    }
}

void FeatureDiagnostics::Report() const noexcept {
    if (!diagnostics::Enabled())
        return;
    for (unsigned feature = 0; feature < Features; ++feature) {
        for (unsigned stage = 0; stage < Stages; ++stage)
            for (unsigned status = 0; status < Statuses; ++status)
                if (counts_[feature][stage][status])
                    diagnostics::Write("feature_counter",
                        {{"feature", FeatureNames[feature]}, {"stage", StageNames[stage]},
                            {"status", StatusNames[status]}, {"count", counts_[feature][stage][status]}});
        diagnostics::Write("feature_evidence_summary",
            {{"feature", FeatureNames[feature]}, {"examples", example_counts_[feature]},
                {"example_limit", ExampleLimit}, {"discarded_examples", discarded_examples_[feature]},
                {"success_examples", example_classes_[feature][0]},
                {"success_example_limit", SuccessExampleLimit},
                {"failure_examples", example_classes_[feature][1]},
                {"failure_example_limit", FailureExampleLimit},
                {"snapshot_unavailable_examples", snapshot_unavailable_examples_[feature]},
                {"snapshot_unavailable_example_limit", SnapshotUnavailableExampleLimit},
                {"discarded_snapshot_unavailable", discarded_snapshot_unavailable_[feature]},
                {"receiver_identities", receiver_counts_[feature]}, {"receiver_limit", ReceiverLimit},
                {"receiver_samples", receiver_samples_[feature]},
                {"receiver_sample_limit", ReceiverSampleLimit},
                {"discarded_receivers", discarded_receivers_[feature]},
                {"metadata_recipe_limit", MetadataLimit},
                {"vtable_target_limit",
                    feature == static_cast<unsigned>(Feature::operator_id)  ? OperatorVtableLimit
                        : feature == static_cast<unsigned>(Feature::weapon) ? WeaponVtableLimit
                                                                            : VtableLimit},
                {"receiver_retry_seconds", ReceiverRetrySeconds}, {"name_contents_recorded", false},
                {"receiver_budget_ms", ReceiverBudgetMilliseconds},
                {"receiver_budget_skips", receiver_budget_skips_[feature]}, {"budget_is_soft", true},
                {"selected_by_reader", false}});
    }
    diagnostics::Write("feature_metadata_execution_summary",
        {{"executions", metadata_trace_.captured_executions},
            {"execution_limit", RuntimeDiagnostics::ExecutionLimit},
            {"read_limit", RuntimeDiagnostics::ReadLimit},
            {"observed_executions", metadata_trace_.observed_executions},
            {"discarded_executions", metadata_trace_.discarded_executions}, {"operational_cpu_used", false}});
}
}
