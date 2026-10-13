#include "ui/overlay.hpp"
#include "core/loader.h"
#include "core/diagnostics.hpp"
#include <exception>

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    base::diagnostics::Initialize();

    struct DiagnosticRun {
        ~DiagnosticRun() { base::diagnostics::Shutdown(); }
    } diagnostic_run;

    try {
        base::diagnostics::Phase("driver startup");
        base::diagnostics::Write("driver_startup_started");
        int r = LoadDriver();
        if (r != 0) {
            const auto error = GetLastError();
            base::diagnostics::Write("driver_startup_failed", {{"step", r}, {"win32", error}});
            char msg[128];
            wsprintfA(msg, "driver load failed (step %d, win32 %lu)", r, error);
            MessageBoxA(nullptr, msg, "lifusbounce", MB_OK | MB_ICONWARNING);
            return 1;
        }
        HANDLE hTest =
            CreateFileW(L"\\\\.\\lifus", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hTest == INVALID_HANDLE_VALUE) {
            const auto error = GetLastError();
            base::diagnostics::Write("driver_device_missing", {{"win32", error}});
            char msg[128];
            wsprintfA(msg, "driver loaded but device missing (win32 %lu)", error);
            MessageBoxA(nullptr, msg, "lifusbounce", MB_OK | MB_ICONWARNING);
            return 1;
        }
        CloseHandle(hTest);
        base::diagnostics::Write("driver_device_ready");
        base::diagnostics::Phase("overlay startup");
        return base::RunOverlay(instance);
    } catch (const std::exception& error) {
        base::diagnostics::Write("application_exception", {{"message", error.what()}});
        MessageBoxA(nullptr, error.what(), "lifusbounce - startup failed", MB_OK | MB_ICONERROR);
    } catch (...) {
        base::diagnostics::Write("application_exception", {{"message", "unknown exception"}});
        MessageBoxW(nullptr, L"startup failed", L"lifusbounce - startup failed", MB_OK | MB_ICONERROR);
    }
    return 1;
}
