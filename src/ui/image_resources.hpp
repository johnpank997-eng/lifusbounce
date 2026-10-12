#pragma once
#include "ui/gfx.hpp"
#include <wincodec.h>

namespace base {
struct ImageResources {
    ImageResources() = default;
    ImageResources(const ImageResources&) = delete;
    ImageResources& operator=(const ImageResources&) = delete;
    ~ImageResources();

    bool Init();
    bool Load(HINSTANCE instance, unsigned resource, ID3D11Device* device,
        ComPtr<ID3D11ShaderResourceView>& destination) const;

private:
    ComPtr<IWICImagingFactory> factory;
    bool owned{};
};
}
