#include "sdk/reader_internal.hpp"

namespace base::sdk {
bool Pointer(Address value) {
    return value > 0x1000 && value < 0x800000000000ull;
}

bool Equivalent(const Environment& a, const Environment& b) {
    return a.parent == b.parent && a.manager == b.manager && a.array == b.array && a.camera == b.camera;
}

bool Finite(skeleton::Point p, float bound) {
    return std::isfinite(p.x) && std::isfinite(p.y) && std::isfinite(p.z) && std::abs(p.x) <= bound &&
        std::abs(p.y) <= bound && std::abs(p.z) <= bound;
}

ProjectionEvidence InspectProjection(const skeleton::Matrix& view, bool transposed) noexcept {
    ProjectionEvidence result;
    if (!std::all_of(view.begin(), view.end(), [](float value) { return std::isfinite(value); }))
        result.rejections |= static_cast<std::uint32_t>(ProjectionRejection::nonfinite);
    std::array<std::array<double, 3>, 4> axes{};
    for (unsigned i = 0; i < 4; ++i) {
        axes[i] = transposed ? std::array<double, 3>{view[i * 4], view[i * 4 + 1], view[i * 4 + 2]}
                             : std::array<double, 3>{view[i], view[i + 4], view[i + 8]};
        result.lengths[i] = std::hypot(axes[i][0], axes[i][1], axes[i][2]);
        if (result.lengths[i] == 0)
            result.rejections |= static_cast<std::uint32_t>(ProjectionRejection::axis0_zero) << i;
    }
    const auto dot = [&](unsigned a, unsigned b) {
        if (result.lengths[a] == 0 || result.lengths[b] == 0)
            return std::numeric_limits<double>::quiet_NaN();
        return (axes[a][0] * axes[b][0] + axes[a][1] * axes[b][1] + axes[a][2] * axes[b][2]) /
            (result.lengths[a] * result.lengths[b]);
    };
    result.dot01 = dot(0, 1);
    result.dot03 = dot(0, 3);
    result.dot13 = dot(1, 3);
    result.dot23 = dot(2, 3);
    if (std::isfinite(result.dot01) && std::abs(result.dot01) >= 0.001)
        result.rejections |= static_cast<std::uint32_t>(ProjectionRejection::dot01);
    if (std::isfinite(result.dot03) && std::abs(result.dot03) >= 0.01)
        result.rejections |= static_cast<std::uint32_t>(ProjectionRejection::dot03);
    if (std::isfinite(result.dot13) && std::abs(result.dot13) >= 0.01)
        result.rejections |= static_cast<std::uint32_t>(ProjectionRejection::dot13);
    if (std::isfinite(result.dot23) && std::abs(result.dot23) <= 0.999)
        result.rejections |= static_cast<std::uint32_t>(ProjectionRejection::dot23);
    return result;
}

bool Projection(const skeleton::Matrix& view) {
    return InspectProjection(view).Accepted();
}

auto Reader::Implementation::Q(Address at) -> Address {
    return Read<Address>(at);
}

auto Reader::Implementation::Evaluate(const locators::PointerDescriptor& path, Address teb, Address object,
    std::string_view stage, std::size_t index) -> Address {
    const auto put = [&](locators::Location at, Address value) {
        if (at.stack)
            cpu.Stack(static_cast<std::uint32_t>(at.slot), value);
        else
            cpu.Set(at.reg, value);
    };
    const auto get = [&](locators::Location at) {
        return at.stack ? cpu.Stack(static_cast<std::uint32_t>(at.slot)) : cpu.Get(at.reg);
    };
    std::vector<Address> seeds;
    seeds.reserve(path.seeds.size());
    const auto seed_stage = stage == "operator_instance" ? "operator_instance_seed"
        : stage == "operator_definition"                 ? "operator_definition_seed"
        : stage == "operator_name_reference"             ? "operator_name_reference_seed"
                                                         : "pose_seed";
    for (const auto& seed : path.seeds) {
        cpu.Reset(teb);
        put(path.input, object);
        const auto result = stage.empty()
            ? cpu.Run(seed.value.code)
            : trace.Execute(cpu, seed.value.code, seed_stage, index * 32 + seeds.size(), module.address);
        if (!result.Complete()) {
            trace.Emulation("pointer_seed_emulation_failed", seeds.size(), result, module.address);
            emulation_error = result;
            throw ReadFailure{ERROR_NOT_SUPPORTED};
        }
        seeds.push_back(get(seed.target));
    }
    cpu.Reset(teb);
    put(path.input, object);
    for (std::size_t j = 0; j < seeds.size(); ++j)
        put(path.seeds[j].target, seeds[j]);
    const auto result =
        stage.empty() ? cpu.Run(path.code) : trace.Execute(cpu, path.code, stage, index, module.address);
    if (!result.Complete()) {
        trace.Emulation("pointer_emulation_failed", 0, result, module.address);
        emulation_error = result;
        throw ReadFailure{ERROR_NOT_SUPPORTED};
    }
    return get(path.output);
}

auto Reader::Implementation::EmulationMessage() const -> std::string {
    if (!emulation_error)
        return "emulation failed";
    const auto& failure = *emulation_error;
    std::array<char, 17> offset{};
    const auto converted =
        std::to_chars(offset.data(), offset.data() + offset.size(), failure.address - module.address, 16);
    const auto name = ZydisMnemonicGetString(failure.mnemonic);
    return "emulation stopped at +0x" + std::string(offset.data(), converted.ptr) + " " +
        (name ? name : "unknown") + " status " + std::to_string(static_cast<unsigned>(failure.status));
}

auto Reader::Implementation::Section(Address at) const -> bool {
    return std::any_of(
        sections.begin(), sections.end(), [&](const auto& s) { return s.first < at && at < s.second; });
}

Reader::Implementation::Implementation(
    const Memory& p, ModuleInfo m, IMAGE_NT_HEADERS64 h, locators::NativeDescriptor n)
    : process(p), module(std::move(m)), header(h), native(std::move(n)), cpu(p) {
    const auto dos = Read<IMAGE_DOS_HEADER>(module.address);
    if (header.FileHeader.NumberOfSections > 96 || !header.FileHeader.NumberOfSections)
        throw ReadFailure{ERROR_BAD_EXE_FORMAT};
    const auto table = module.address + static_cast<std::uint32_t>(dos.e_lfanew) + 24 +
        header.FileHeader.SizeOfOptionalHeader;
    const auto records = Array<IMAGE_SECTION_HEADER>(table, header.FileHeader.NumberOfSections);
    for (const auto& s : records) {
        if (std::memcmp(s.Name, ".data\0", 6) != 0 && std::memcmp(s.Name, ".rdata\0", 7) != 0)
            continue;
        if (s.VirtualAddress >= module.size || s.Misc.VirtualSize > module.size - s.VirtualAddress)
            throw ReadFailure{ERROR_BAD_EXE_FORMAT};
        sections.emplace_back(
            module.address + s.VirtualAddress, module.address + s.VirtualAddress + s.Misc.VirtualSize);
    }
    if (sections.size() != 2)
        throw ReadFailure{ERROR_BAD_EXE_FORMAT};
    const auto directory = header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_TLS_DIRECTORY64) ||
        directory.VirtualAddress >= module.size ||
        sizeof(IMAGE_TLS_DIRECTORY64) > module.size - directory.VirtualAddress)
        throw ReadFailure{ERROR_BAD_EXE_FORMAT};
    const auto tls = Read<IMAGE_TLS_DIRECTORY64>(module.address + directory.VirtualAddress);
    tls_index = Read<std::uint32_t>(tls.AddressOfIndex);
    if (tls_index > 100 || native.roots.empty() || native.roots.size() != native.contexts.size() ||
        native.cameras.empty() || native.metadata.empty() || native.managers.empty() ||
        native.arrays.empty() || native.poses.empty() || native.rigs.empty())
        throw ReadFailure{ERROR_NOT_SUPPORTED};
}
}
