#include "ui/gfx.hpp"
#include "ui/operator_badges.hpp"
#include "sdk/operators.hpp"
#include <cstdint>

namespace base {
bool OperatorBadges::Init(HINSTANCE instance, ID3D11Device* device, const ImageResources& images) {
    for (std::size_t i = 0; i < assets.size(); ++i)
        if (!images.Load(instance, assets[i].resource, device, textures[i]))
            return false;
    return true;
}

ID3D11ShaderResourceView* OperatorBadges::Get(std::uint32_t id) const noexcept {
    const auto* value = sdk::operators::Find(id);
    if (!value)
        return nullptr;
    for (std::size_t i = 0; i < assets.size(); ++i)
        if (assets[i].name == value->badge)
            return textures[i].Get();
    return nullptr;
}

}
