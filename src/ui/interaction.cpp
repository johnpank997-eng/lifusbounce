#include "ui/overlay_internal.hpp"
#include <imgui_impl_win32.h>
#include <windowsx.h>
#include <cmath>
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace base {
auto Interaction::Owns(HWND window) const -> bool {
    DWORD pid{};
    if (window)
        GetWindowThreadProcessId(window, &pid);
    return game_pid && pid == game_pid;
}

auto Interaction::ForegroundGame() const -> bool {
    const auto foreground = GetForegroundWindow();
    if (!game || !IsWindowVisible(game) || IsIconic(game))
        return false;
    const auto now = std::chrono::steady_clock::now();
    if (!foreground)
        return now - last_owned < std::chrono::milliseconds(50);
    if (!Owns(foreground))
        return false;
    last_owned = now;
    return true;
}

auto Interaction::Interactive() const -> bool {
    return (loading || menu) && ForegroundGame();
}

bool Interaction::ToggleMenu() {
    if (loading)
        return false;
    menu = !menu;
    return true;
}

void Interaction::BeginLoading() {
    loading = true;
    menu = false;
    menu_alpha = 0.0f;
    ReleaseInput();
}

void Interaction::UpdateLoading(float progress) {
    if (loading && std::isfinite(progress) && progress >= 1.0f) {
        loading = false;
        ReleaseInput();
    }
}

auto Interaction::ReleaseInput() -> void {
    if (GetCapture() == panel || GetCapture() == drawing)
        ReleaseCapture();
    mouse_down.fill(false);
    mouse_owned.fill(false);
    input_active = false;
    if (!ImGui::GetCurrentContext())
        return;
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddFocusEvent(false);
}

auto Interaction::SyncInput() -> void {
    const bool wanted = Interactive();
    if (wanted == input_active)
        return;
    ReleaseInput();
    if (!wanted)
        return;
    constexpr int buttons[]{VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1, VK_XBUTTON2};
    for (unsigned button = 0; button < mouse_down.size(); ++button)
        mouse_down[button] = (GetAsyncKeyState(buttons[button]) & 0x8000) != 0;
    input_active = true;
    ImGui::GetIO().AddFocusEvent(true);
}

auto Interaction::PollMouse() -> void {
    if (!input_active)
        return;
    POINT mouse{};
    const bool positioned = GetCursorPos(&mouse) != FALSE;
    const auto hovered_window = positioned ? WindowFromPoint(mouse) : nullptr;
    const bool hovered = hovered_window == panel;
    if (positioned && ScreenToClient(drawing, &mouse))
        ImGui::GetIO().AddMousePosEvent(static_cast<float>(mouse.x), static_cast<float>(mouse.y));
    constexpr int buttons[]{VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1, VK_XBUTTON2};
    for (unsigned button = 0; button < mouse_down.size(); ++button) {
        const bool down = (GetAsyncKeyState(buttons[button]) & 0x8000) != 0;
        if (down != mouse_down[button])
            mouse_owned[button] = down && hovered;
        mouse_down[button] = down;
        ImGui::GetIO().AddMouseButtonEvent(static_cast<int>(button), down && mouse_owned[button]);
    }
}

auto Interaction::Hide() -> void {
    menu_alpha = 0.0f;
    applied = {-1, -1, -1, -1};
    ReleaseInput();
    ShowWindow(panel, SW_HIDE);
    ShowWindow(drawing, SW_HIDE);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    const auto state = reinterpret_cast<Interaction*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto create = reinterpret_cast<CREATESTRUCTW*>(lp);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    if (state && window == state->panel) {
        if (message == WM_MOUSEACTIVATE)
            return MA_NOACTIVATE;
        if (message == WM_NCHITTEST && !state->Interactive())
            return HTTRANSPARENT;
        if (message == WM_SETCURSOR && LOWORD(lp) == HTCLIENT && state->Interactive()) {
            SetCursor(LoadCursorW(nullptr, IDC_ARROW));
            return TRUE;
        }
        if (message == WM_CANCELMODE || message == WM_CAPTURECHANGED)
            state->ReleaseInput();
        if (message == WM_SETFOCUS || message == WM_KILLFOCUS || message == WM_ACTIVATEAPP)
            return 0;
        if (message == WM_MOUSEMOVE || message == WM_NCMOUSEMOVE || message == WM_MOUSELEAVE ||
            message == WM_NCMOUSELEAVE)
            return 0;
        if (message >= WM_MOUSEFIRST && message <= WM_MOUSELAST && message != WM_MOUSEWHEEL &&
            message != WM_MOUSEHWHEEL)
            return 0;
        if (!state->Interactive() &&
            ((message >= WM_MOUSEFIRST && message <= WM_MOUSELAST) ||
                (message >= WM_KEYFIRST && message <= WM_KEYLAST)))
            return 0;
        if (ImGui_ImplWin32_WndProcHandler(window, message, wp, lp))
            return 1;
    }
    switch (message) {
    case WM_SIZE:
        return 0;
    case WM_MOUSEACTIVATE:
        return MA_NOACTIVATE;
    case WM_NCHITTEST:
        if (state && window == state->drawing)
            return HTTRANSPARENT;
        break;
    case WM_SYSCOMMAND:
        if ((wp & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        if (!state || window == state->drawing)
            PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}
}
