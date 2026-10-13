#pragma once
#include "core/diagnostics.hpp"

namespace base::diagnostics {
struct Retention {
    std::uint64_t removed{};
    DWORD error{};
};

Retention Prune(const std::wstring& directory) noexcept;
bool EvidenceRecord(
    std::string_view event, std::initializer_list<Field> fields, std::string_view payload = {}) noexcept;
bool KnownArtifact(std::string_view key);
void RememberArtifact(std::string_view key);
}
