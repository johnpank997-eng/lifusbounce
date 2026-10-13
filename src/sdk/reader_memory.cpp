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

bool Projection(const skeleton::Matrix& view) {
    if (!std::all_of(view.begin(), view.end(), [](float v) { return std::isfinite(v); }))
        return false;
    std::array<std::array<double, 3>, 4> axes{};
    std::array<double, 4> length{};
    for (unsigned i = 0; i < 4; ++i) {
        axes[i] = {view[i], view[i + 4], view[i + 8]};
        length[i] = std::hypot(axes[i][0], axes[i][1], axes[i][2]);
        if (length[i] == 0)
            return false;
    }
    const auto dot = [&](unsigned a, unsigned b) {
        return (axes[a][0] * axes[b][0] + axes[a][1] * axes[b][1] + axes[a][2] * axes[b][2]) /
            (length[a] * length[b]);
    };
    return std::abs(dot(0, 1)) < 0.001 && std::abs(dot(0, 3)) < 0.01 && std::abs(dot(1, 3)) < 0.01 &&
        std::abs(dot(2, 3)) > 0.999;
}

auto Reader::Implementation::Q(Address at) -> Address {
    return Read<Address>(at);
}

auto Reader::Implementation::Evaluate(const locators::PointerDescriptor& path, Address teb, Address object)
    -> Address {
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
    for (const auto& seed : path.seeds) {
        cpu.Reset(teb);
        put(path.input, object);
        const auto result = cpu.Run(seed.value.code);
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
    const auto result = cpu.Run(path.code);
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
