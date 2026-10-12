#include "sdk/reader_internal.hpp"

namespace base::sdk {
auto Reader::Implementation::TypeInfo(Address object, Address* out_vtable) -> Address {
    if (!metadata)
        throw ReadFailure{ERROR_NOT_READY};
    const auto vtable = Q(object);
    if (out_vtable)
        *out_vtable = vtable;
    if (!Section(vtable))
        throw ReadFailure{ERROR_INVALID_DATA};
    const auto info = Q(vtable + metadata->table_field);
    if (!Section(info))
        throw ReadFailure{ERROR_INVALID_DATA};
    return info;
}

auto Reader::Implementation::Hash(Address object) -> std::uint32_t {
    const auto vtable = Q(object);
    if (const auto found = hashes.find(vtable); found != hashes.end())
        return found->second;
    TypeInfo(object);
    cpu.Reset();
    cpu.Set(ZYDIS_REGISTER_RCX, object);
    const auto result = cpu.Run(metadata->decode.code);
    if (!result.Complete())
        throw ReadFailure{ERROR_NOT_SUPPORTED};
    const auto value = static_cast<std::uint32_t>(cpu.Get(metadata->decode.output));
    hashes.emplace(vtable, value);
    return value;
}

auto Reader::Implementation::Extent(Address object, Address limit) -> Address {
    const auto vtable = Q(object);
    Address value{};
    if (const auto found = extents.find(vtable); found != extents.end())
        value = found->second;
    else {
        value = Q(TypeInfo(object) + 0x24);
        extents.emplace(vtable, value);
    }
    if (!value || value > limit)
        throw ReadFailure{ERROR_INVALID_DATA};
    return value;
}
}
