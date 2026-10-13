#include "sdk/diagnostics.hpp"
#include "core/diagnostics.hpp"
#include <cstring>

namespace base::sdk {
bool ReportImage(const Memory& process, const ModuleInfo& module, const IMAGE_NT_HEADERS64& header,
    std::span<const std::byte> code, std::span<const locators::FunctionRecord> functions,
    std::string_view code_hash, std::stop_token stop) noexcept {
    if (!diagnostics::Enabled())
        return false;
    diagnostics::Phase("saving native evidence", .60f);
    diagnostics::MemoryStatus("before image capture");
    bool code_complete{}, functions_complete{}, headers_complete{}, rdata_complete{};
    diagnostics::Write("image_capture_begin",
        {{"image_id", code_hash}, {"loaded_base", diagnostics::Hex(module.address)},
            {"image_size", module.size}, {"code_rva", header.OptionalHeader.BaseOfCode},
            {"code_size", code.size()}, {"function_records", functions.size()},
            {"transport", "existing lifus driver; read-only"}});
    try {
        code_complete =
            diagnostics::Artifact("game_code", header.OptionalHeader.BaseOfCode, code, stop, code_hash);
        functions_complete = diagnostics::Artifact("functions",
            header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress,
            std::as_bytes(functions), stop);
        const auto size = header.OptionalHeader.SizeOfHeaders;
        if (size && size <= 1024 * 1024 && size <= module.size) {
            std::vector<std::byte> bytes(size);
            const auto read = process.ReadBytes(module.address, bytes);
            if (read.Complete()) {
                headers_complete = diagnostics::Artifact("headers", 0, bytes, stop);
                if (size >= sizeof(IMAGE_DOS_HEADER)) {
                    IMAGE_DOS_HEADER dos{};
                    std::memcpy(&dos, bytes.data(), sizeof(dos));
                    const auto table = static_cast<std::uint64_t>(dos.e_lfanew) + 24 +
                        header.FileHeader.SizeOfOptionalHeader;
                    if (dos.e_lfanew >= 0 && table <= size && header.FileHeader.NumberOfSections <= 96 &&
                        std::uint64_t(header.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER) <=
                            size - table) {
                        for (unsigned i = 0; i < header.FileHeader.NumberOfSections && !stop.stop_requested();
                            ++i) {
                            IMAGE_SECTION_HEADER section{};
                            std::memcpy(
                                &section, bytes.data() + table + i * sizeof(section), sizeof(section));
                            const std::string name(reinterpret_cast<const char*>(section.Name),
                                strnlen(reinterpret_cast<const char*>(section.Name), sizeof(section.Name)));
                            diagnostics::Write("image_section",
                                {{"name", name}, {"rva", diagnostics::Hex(section.VirtualAddress)},
                                    {"virtual_size", section.Misc.VirtualSize},
                                    {"raw_size", section.SizeOfRawData},
                                    {"flags", diagnostics::Hex(section.Characteristics)}});
                            if (name == ".rdata" && section.Misc.VirtualSize &&
                                section.Misc.VirtualSize <= 32 * 1024 * 1024 &&
                                section.VirtualAddress < module.size &&
                                section.Misc.VirtualSize <= module.size - section.VirtualAddress) {
                                std::vector<std::byte> data(section.Misc.VirtualSize);
                                const auto got =
                                    process.ReadBytes(module.address + section.VirtualAddress, data);
                                if (got.Complete())
                                    rdata_complete =
                                        diagnostics::Artifact("rdata", section.VirtualAddress, data, stop);
                                else
                                    diagnostics::Write("image_capture_read_error",
                                        {{"section", name}, {"win32", got.error},
                                            {"rva", diagnostics::Hex(section.VirtualAddress)},
                                            {"transferred", got.transferred}});
                            }
                        }
                    }
                }
            } else
                diagnostics::Write("image_capture_read_error",
                    {{"section", "headers"}, {"win32", read.error}, {"transferred", read.transferred}});
        }
    } catch (const std::exception& error) {
        diagnostics::Exception("image capture", error);
    }
    const bool complete = code_complete && functions_complete && headers_complete;
    diagnostics::Write("image_capture_end",
        {{"image_id", code_hash}, {"complete", complete}, {"code_complete", code_complete},
            {"functions_complete", functions_complete}, {"headers_complete", headers_complete},
            {"rdata_complete", rdata_complete}, {"cancelled", stop.stop_requested()}});
    return complete;
}
}
