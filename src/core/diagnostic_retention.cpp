#include "core/diagnostics_internal.hpp"
#include <filesystem>
#include <regex>

namespace base::diagnostics {
Retention Prune(const std::wstring& directory) noexcept {
    Retention result;
    try {
        const auto folder = std::filesystem::absolute(directory).lexically_normal();
        const std::wregex owned(
            LR"(^lifus-diagnostic-[0-9]{8}T[0-9]{6}-[0-9]{3}Z-[0-9]+-[0-9]+\.(jsonl|zip)$)");
        for (const auto& entry : std::filesystem::directory_iterator(folder)) {
            const auto path = entry.path().lexically_normal();
            if (path.parent_path() != folder || !std::regex_match(path.filename().wstring(), owned))
                continue;
            const auto flags = GetFileAttributesW(path.c_str());
            if (flags == INVALID_FILE_ATTRIBUTES ||
                flags & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
                continue;
            if (DeleteFileW(path.c_str()))
                ++result.removed;
            else if (!result.error)
                result.error = GetLastError();
        }
    } catch (const std::filesystem::filesystem_error& error) {
        result.error = static_cast<DWORD>(error.code().value());
    } catch (...) {
        result.error = ERROR_NOT_ENOUGH_MEMORY;
    }
    return result;
}
}
