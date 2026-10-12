#pragma once
#include "core/handle.hpp"
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dcomp.h>
#include <wrl/client.h>
#include <chrono>

namespace base {
template <class t> using ComPtr = Microsoft::WRL::ComPtr<t>;

struct Gfx {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGISwapChain1> swap_chain;
    ComPtr<IDXGISwapChain1> menu_chain;
    ComPtr<ID3D11RenderTargetView> target;
    ComPtr<ID3D11RenderTargetView> menu_target;
    ComPtr<IDCompositionDevice> composition;
    ComPtr<IDCompositionTarget> composition_target;
    ComPtr<IDCompositionTarget> menu_composition_target;
    ComPtr<IDCompositionVisual> visual;
    ComPtr<IDCompositionVisual> menu_visual;
    UniqueHandle timer;
    HMONITOR monitor{};
    UINT target_width{}, target_height{};
    std::chrono::steady_clock::duration interval = std::chrono::milliseconds(16);
    std::chrono::steady_clock::time_point next_frame{};

    DWORD WaitFrame(HWND game);
    bool CreateTarget();
    bool Resize(UINT w, UINT h);
    bool Init(HWND window, HWND panel);
};

bool TransparentBacking(HWND window, int w, int h, POINT origin);
}
