#pragma once
#include <ntifs.h>
#include <wdmsec.h>

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess,
    PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

NTKERNELAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength,
    PULONG ReturnLength);

NTKERNELAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation,
    ULONG ThreadInformationLength, PULONG ReturnLength);

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION (0x0040)
#endif

#ifndef DECLARE_CONST_UNICODE_STRING
#define DECLARE_CONST_UNICODE_STRING(_variablename, _string)                                                 \
    const WCHAR _variablename##_buffer[] = _string;                                                          \
    const UNICODE_STRING _variablename = {                                                                   \
        (USHORT)(sizeof(_string) - sizeof(WCHAR)), (USHORT)(sizeof(_string)), (PWCH)_variablename##_buffer}
#endif

#define DEVICE_NAME L"\\Device\\lifus"
#define SYMBOLIC_NAME L"\\DosDevices\\lifus"

#define IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BULK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THREADS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_TRANSFER_SIZE (PAGE_SIZE * 256)
#define MAX_BULK_OPERATIONS 64
#define MAX_PROCESS_NAME_LENGTH 260
#define MAX_PROCESS_LIST_CAPACITY 2048
#define MAX_REGION_LIST_CAPACITY 8192
#define MAX_THREAD_LIST_CAPACITY 2048

typedef struct _RW_REQUEST {
    ULONG ProcessId;
    ULONG64 Address;
    ULONG64 Buffer;
    SIZE_T Size;
    BOOLEAN Write;
    NTSTATUS Status;
} RW_REQUEST, *PRW_REQUEST;

typedef struct _BULK_REQUEST {
    ULONG Count;
    RW_REQUEST Operations[MAX_BULK_OPERATIONS];
} BULK_REQUEST, *PBULK_REQUEST;

typedef struct _PROC_ENTRY {
    ULONG ProcessId;
    WCHAR Name[MAX_PROCESS_NAME_LENGTH];
} PROC_ENTRY, *PPROC_ENTRY;

typedef struct _PROC_LIST_REQUEST {
    ULONG Count;
    PROC_ENTRY Processes[1];
} PROC_LIST_REQUEST, *PPROC_LIST_REQUEST;

typedef struct _REGION_INFO {
    ULONG64 BaseAddress;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} REGION_INFO, *PREGION_INFO;

typedef struct _REGION_REQUEST {
    ULONG ProcessId;
    ULONG64 StartAddress;
    ULONG Count;
    REGION_INFO Regions[1];
} REGION_REQUEST, *PREGION_REQUEST;

typedef struct _THREAD_INFO {
    ULONG ThreadId;
    ULONG64 TebBaseAddress;
} THREAD_INFO, *PTHREAD_INFO;

typedef struct _THREAD_LIST_REQUEST {
    ULONG ProcessId;
    ULONG Count;
    THREAD_INFO Threads[1];
} THREAD_LIST_REQUEST, *PTHREAD_LIST_REQUEST;

typedef struct _SYSTEM_THREAD_INFO {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFO, *PSYSTEM_THREAD_INFO;

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _THREAD_BASIC_INFO {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} THREAD_BASIC_INFO, *PTHREAD_BASIC_INFO;
