#include "ui/overlay.hpp"
#include "core/loader.h"
#include <exception>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    try {
        int r = LoadDriver();
        if (r != 0) {
            char msg[128];
            wsprintfA(msg, "driver load failed (step %d, win32 %lu)", r, GetLastError());
            MessageBoxA(nullptr, msg, "lifusbounce", MB_OK | MB_ICONWARNING);
            return 1;
        }
        HANDLE hTest =
            CreateFileW(L"\\\\.\\lifus", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hTest == INVALID_HANDLE_VALUE) {
            char msg[128];
            wsprintfA(msg, "driver loaded but device missing (win32 %lu)", GetLastError());
            MessageBoxA(nullptr, msg, "lifusbounce", MB_OK | MB_ICONWARNING);
            return 1;
        }
        CloseHandle(hTest);
        return base::RunOverlay(instance);
    } catch (const std::exception& error) {
        MessageBoxA(nullptr, error.what(), "lifusbounce - startup failed", MB_OK | MB_ICONERROR);
    } catch (...) {
        MessageBoxW(nullptr, L"startup failed", L"lifusbounce - startup failed", MB_OK | MB_ICONERROR);
    }
    return 1;
}
