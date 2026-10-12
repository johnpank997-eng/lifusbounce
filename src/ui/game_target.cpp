#include "ui/overlay_internal.hpp"
#include <imgui_impl_win32.h>
#include <windowsx.h>
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace base {
struct GameWindowSearch {
    DWORD pid{};
    HWND window{};
    LONG area{};
};

BOOL CALLBACK FindGameWindow(HWND window, LPARAM parameter) {
    auto& search = *reinterpret_cast<GameWindowSearch*>(parameter);
    DWORD pid{};
    GetWindowThreadProcessId(window, &pid);
    if (pid != search.pid || !IsWindowVisible(window) || GetWindow(window, GW_OWNER))
        return TRUE;
    RECT rect{};
    if (!GetClientRect(window, &rect))
        return TRUE;
    const LONG width = rect.right - rect.left, height = rect.bottom - rect.top;
    if (width <= 0 || height <= 0 || width > 32768 || height > 32768)
        return TRUE;
    const LONG area = width * height;
    if (area > search.area) {
        search.window = window;
        search.area = area;
    }
    return TRUE;
}

HWND GameWindow(DWORD pid) {
    GameWindowSearch search{pid};
    if (pid)
        EnumWindows(FindGameWindow, reinterpret_cast<LPARAM>(&search));
    return search.window;
}

void GameTarget::Update() {
    if (process) {
        const auto state = WaitForSingleObject(process.Get(), 0);
        if (state != WAIT_TIMEOUT) {
            closed = true;
            return;
        }
    }
    const auto now = std::chrono::steady_clock::now();
    if (now < next_search && (!window || IsWindow(window)))
        return;
    next_search = now + std::chrono::milliseconds(500);
    if (!attached || !process) {
        const auto found = sdk::FindProcess();
        if (!found)
            return;
        if (attached && *found != pid) {
            closed = true;
            return;
        }
        if (!*found)
            return;
        pid = *found;
        process.Reset(OpenProcess(SYNCHRONIZE, FALSE, pid));
        attached = true;
    }
    window = GameWindow(pid);
}

}
