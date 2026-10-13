#include "core/mem.hpp"
#include <winioctl.h>
#include <tlhelp32.h>
#include <limits>

namespace base {
namespace {

constexpr DWORD ctl_read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD ctl_procs = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr DWORD ctl_threads = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS);

constexpr std::size_t max_chunk = 1024 * 1024;

#pragma pack(push, 8)

struct RwReq {
    ULONG pid;
    ULONG64 addr;
    ULONG64 buf;
    SIZE_T size;
    BOOLEAN write;
    LONG status;
};

struct Dproc {
    ULONG pid;
    WCHAR name[260];
};

struct Dthread {
    ULONG tid;
    ULONG64 teb;
};

#pragma pack(pop)

DWORD NtstatusError(LONG status) {
    using Fn = ULONG(NTAPI*)(LONG);
    static const auto convert =
        reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
    return convert ? convert(status) : ERROR_GEN_FAILURE;
}

UniqueHandle OpenDriver() {
    return UniqueHandle(
        CreateFileW(L"\\\\.\\lifus", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
}

DWORD DrvRead(HANDLE h, ULONG pid, std::uintptr_t addr, void* out, std::size_t n) {
    RwReq r{};
    r.pid = pid;
    r.addr = addr;
    r.buf = reinterpret_cast<ULONG64>(out);
    r.size = n;
    DWORD bytes = 0;
    if (!DeviceIoControl(h, ctl_read, &r, sizeof(r), &r, sizeof(r), &bytes, nullptr))
        return GetLastError();
    if (r.status < 0)
        return NtstatusError(r.status);
    return ERROR_SUCCESS;
}

std::uintptr_t FirstTeb(HANDLE h, DWORD pid, DWORD& error) {
    constexpr ULONG cap = 16;
    constexpr DWORD hdr = 2 * sizeof(ULONG);
    constexpr DWORD buf_size = hdr + cap * sizeof(Dthread);
    std::byte raw[buf_size]{};
    auto* fields = reinterpret_cast<ULONG*>(raw);
    fields[0] = pid;
    fields[1] = cap;
    DWORD bytes = 0;
    if (!DeviceIoControl(h, ctl_threads, raw, buf_size, raw, buf_size, &bytes, nullptr)) {
        error = GetLastError();
        return 0;
    }
    if (!fields[1]) {
        error = ERROR_NOT_FOUND;
        return 0;
    }
    auto* t = reinterpret_cast<const Dthread*>(raw + hdr);
    error = ERROR_SUCCESS;
    return static_cast<std::uintptr_t>(t[0].teb);
}
}

std::wstring ErrorText(DWORD error) {
    if (error == ERROR_SUCCESS)
        return L"success";
    wchar_t* message = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
        error, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring result =
        length && message ? std::wstring(message, length) : L"win32 error " + std::to_wstring(error);
    if (message)
        LocalFree(message);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n'))
        result.pop_back();
    return result;
}

std::vector<ProcessInfo> Processes(DWORD& error) {
    std::vector<ProcessInfo> result;
    UniqueHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) {
        error = GetLastError();
        return result;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.Get(), &pe)) {
        error = GetLastError();
        return result;
    }
    do {
        result.push_back({pe.th32ProcessID, pe.szExeFile});
    } while (Process32NextW(snap.Get(), &pe));
    error = ERROR_SUCCESS;
    return result;
}

DWORD Memory::Attach(DWORD pid) noexcept {
    Detach();
    statistics_ = {};
    auto drv = OpenDriver();
    if (!drv)
        return GetLastError();
    driver_ = std::move(drv);
    pid_ = pid;
    return ERROR_SUCCESS;
}

ReadResult Memory::ReadBytes(std::uintptr_t address, std::span<std::byte> output) const noexcept {
    ++statistics_.calls;
    statistics_.requested += output.size();
    const auto finish = [&](ReadResult result) {
        statistics_.transferred += result.transferred;
        if (result.error) {
            ++statistics_.failures;
            statistics_.last_error = result.error;
            for (auto& [error, count] : statistics_.errors)
                if (!count || error == result.error) {
                    error = result.error;
                    ++count;
                    break;
                }
        }
        return result;
    };
    if (!driver_)
        return finish({0, ERROR_INVALID_HANDLE});
    if (output.empty())
        return {};
    if (address > std::numeric_limits<std::uintptr_t>::max() - (output.size() - 1))
        return finish({0, ERROR_ARITHMETIC_OVERFLOW});
    std::size_t done = 0;
    while (done < output.size()) {
        const auto n = std::min(max_chunk, output.size() - done);
        const auto err = DrvRead(driver_.Get(), pid_, address + done, output.data() + done, n);
        if (err)
            return finish({done, err});
        done += n;
    }
    return finish({done, ERROR_SUCCESS});
}

std::vector<ModuleInfo> Memory::Modules(DWORD& error) const {
    std::vector<ModuleInfo> result;
    if (!driver_) {
        error = ERROR_INVALID_HANDLE;
        return result;
    }
    const auto teb = FirstTeb(driver_.Get(), pid_, error);
    if (!teb)
        return result;
    std::uintptr_t peb = 0;
    auto err = DrvRead(driver_.Get(), pid_, teb + 0x60, &peb, sizeof(peb));
    if (err || !peb) {
        error = err ? err : ERROR_BAD_FORMAT;
        return result;
    }
    std::uintptr_t ldr = 0;
    err = DrvRead(driver_.Get(), pid_, peb + 0x18, &ldr, sizeof(ldr));
    if (err || !ldr) {
        error = err ? err : ERROR_BAD_FORMAT;
        return result;
    }
    const auto head = ldr + 0x10;
    std::uintptr_t entry = 0;
    err = DrvRead(driver_.Get(), pid_, head, &entry, sizeof(entry));
    if (err || !entry) {
        error = err ? err : ERROR_BAD_FORMAT;
        return result;
    }
    for (unsigned i = 0; i < 512 && entry && entry != head; ++i) {
        std::byte raw[0x68]{};
        if (DrvRead(driver_.Get(), pid_, entry, raw, sizeof(raw)))
            break;
        const auto base = *reinterpret_cast<std::uintptr_t*>(raw + 0x30);
        const auto size = *reinterpret_cast<ULONG*>(raw + 0x40);
        const auto len = *reinterpret_cast<USHORT*>(raw + 0x58);
        const auto buf = *reinterpret_cast<std::uintptr_t*>(raw + 0x60);
        if (!base)
            break;
        std::wstring name;
        if (len > 0 && len <= 520 && buf) {
            name.resize(len / sizeof(wchar_t));
            if (DrvRead(driver_.Get(), pid_, buf, name.data(), len))
                name.clear();
        }
        if (!name.empty())
            result.push_back({std::move(name), base, static_cast<std::size_t>(size)});
        const auto next = *reinterpret_cast<std::uintptr_t*>(raw);
        if (!next || next == entry)
            break;
        entry = next;
    }
    error = result.empty() ? ERROR_NOT_FOUND : ERROR_SUCCESS;
    return result;
}

std::optional<bool> Memory::Is64Bit(DWORD& error) const noexcept {
    if (!driver_) {
        error = ERROR_INVALID_HANDLE;
        return std::nullopt;
    }
    const auto teb = FirstTeb(driver_.Get(), pid_, error);
    if (!teb)
        return std::nullopt;
    std::uintptr_t peb = 0;
    if (DrvRead(driver_.Get(), pid_, teb + 0x60, &peb, sizeof(peb)) || !peb) {
        error = ERROR_BAD_FORMAT;
        return std::nullopt;
    }
    std::uintptr_t image_base = 0;
    if (DrvRead(driver_.Get(), pid_, peb + 0x10, &image_base, sizeof(image_base)) || !image_base) {
        error = ERROR_BAD_FORMAT;
        return std::nullopt;
    }
    IMAGE_DOS_HEADER dos{};
    if (DrvRead(driver_.Get(), pid_, image_base, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        error = ERROR_BAD_FORMAT;
        return std::nullopt;
    }

    struct {
        DWORD sig;
        WORD machine;
    } nt{};

    if (DrvRead(driver_.Get(), pid_, image_base + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.sig != IMAGE_NT_SIGNATURE) {
        error = ERROR_BAD_FORMAT;
        return std::nullopt;
    }
    if (nt.machine != IMAGE_FILE_MACHINE_AMD64 && nt.machine != IMAGE_FILE_MACHINE_I386) {
        error = ERROR_NOT_SUPPORTED;
        return std::nullopt;
    }
    error = ERROR_SUCCESS;
    return nt.machine == IMAGE_FILE_MACHINE_AMD64;
}

std::vector<ThreadEntry> Memory::Threads(DWORD& error) const {
    std::vector<ThreadEntry> result;
    if (!driver_) {
        error = ERROR_INVALID_HANDLE;
        return result;
    }
    constexpr ULONG cap = 2048;
    constexpr DWORD hdr = 2 * sizeof(ULONG);
    constexpr DWORD buf_size = hdr + cap * sizeof(Dthread);
    std::vector<std::byte> raw(buf_size, std::byte{0});
    auto* fields = reinterpret_cast<ULONG*>(raw.data());
    fields[0] = pid_;
    fields[1] = cap;
    DWORD bytes = 0;
    if (!DeviceIoControl(
            driver_.Get(), ctl_threads, raw.data(), buf_size, raw.data(), buf_size, &bytes, nullptr)) {
        error = GetLastError();
        return result;
    }
    const auto count = fields[1];
    auto* entries = reinterpret_cast<const Dthread*>(raw.data() + hdr);
    for (ULONG i = 0; i < count; ++i)
        result.push_back({entries[i].tid, static_cast<std::uintptr_t>(entries[i].teb)});
    error = ERROR_SUCCESS;
    return result;
}
}
