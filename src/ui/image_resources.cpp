#include "ui/image_resources.hpp"
#include <vector>

namespace base {
ImageResources::~ImageResources() {
    factory.Reset();
    if (owned)
        CoUninitialize();
}

bool ImageResources::Init() {
    if (factory)
        return true;
    if (!owned) {
        const auto result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        owned = SUCCEEDED(result);
        if (FAILED(result) && result != RPC_E_CHANGED_MODE)
            return false;
    }
    return SUCCEEDED(CoCreateInstance(
        CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(factory.GetAddressOf())));
}

bool ImageResources::Load(HINSTANCE instance, unsigned resource_id, ID3D11Device* device,
    ComPtr<ID3D11ShaderResourceView>& destination) const {
    if (!factory || !device)
        return false;
    const auto resource = FindResourceW(instance, MAKEINTRESOURCEW(resource_id), RT_RCDATA);
    const auto loaded = resource ? LoadResource(instance, resource) : nullptr;
    auto* data = loaded ? static_cast<BYTE*>(LockResource(loaded)) : nullptr;
    const auto size = resource ? SizeofResource(instance, resource) : 0;
    if (!data || !size)
        return false;
    ComPtr<IWICStream> stream;
    ComPtr<IWICBitmapDecoder> decoder;
    ComPtr<IWICBitmapFrameDecode> frame;
    ComPtr<IWICFormatConverter> converter;
    UINT width{}, height{};
    if (FAILED(factory->CreateStream(stream.GetAddressOf())) ||
        FAILED(stream->InitializeFromMemory(data, size)) ||
        FAILED(factory->CreateDecoderFromStream(
            stream.Get(), nullptr, WICDecodeMetadataCacheOnLoad, decoder.GetAddressOf())) ||
        FAILED(decoder->GetFrame(0, frame.GetAddressOf())) || FAILED(frame->GetSize(&width, &height)) ||
        !width || !height || width > 2048 || height > 2048 ||
        FAILED(factory->CreateFormatConverter(converter.GetAddressOf())) ||
        FAILED(converter->Initialize(frame.Get(), GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone,
            nullptr, 0.0, WICBitmapPaletteTypeCustom)))
        return false;
    const UINT pitch = width * 4;
    std::vector<BYTE> pixels(static_cast<std::size_t>(pitch) * height);
    if (FAILED(converter->CopyPixels(nullptr, pitch, static_cast<UINT>(pixels.size()), pixels.data())))
        return false;
    D3D11_TEXTURE2D_DESC description{};
    description.Width = width;
    description.Height = height;
    description.MipLevels = description.ArraySize = description.SampleDesc.Count = 1;
    description.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.Usage = D3D11_USAGE_IMMUTABLE;
    description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    const D3D11_SUBRESOURCE_DATA source{pixels.data(), pitch, 0};
    ComPtr<ID3D11Texture2D> texture;
    ComPtr<ID3D11ShaderResourceView> view;
    if (FAILED(device->CreateTexture2D(&description, &source, texture.GetAddressOf())) ||
        FAILED(device->CreateShaderResourceView(texture.Get(), nullptr, view.GetAddressOf())))
        return false;
    destination = std::move(view);
    return true;
}
}
