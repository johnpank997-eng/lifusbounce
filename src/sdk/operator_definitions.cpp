#include "sdk/operator_definitions.hpp"

namespace base::sdk::operators {
std::uint32_t DefinitionIdentity(std::uint64_t uid) {
    for (const auto& value : definitions)
        if (value.uid == uid)
            return value.id;
    return 0;
}

std::uint32_t NameDefinitionIdentity(std::uint64_t uid) {
    for (const auto& value : name_definitions)
        if (value.uid == uid)
            return value.id;
    return 0;
}
}
