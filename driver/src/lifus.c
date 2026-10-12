#include "lifus.h"
#pragma warning(disable : 4996)

NTSTATUS ReadWriteMemory(PRW_REQUEST Req) {
    PEPROCESS TargetProcess = NULL;
    PEPROCESS ClientProcess = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T bytesCopied = 0;
    if (!Req || Req->Size == 0 || Req->Size > MAX_TRANSFER_SIZE)
        return STATUS_INVALID_PARAMETER;
    if (Req->Address == 0 || Req->Buffer == 0)
        return STATUS_INVALID_PARAMETER;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &TargetProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ClientProcess = PsGetCurrentProcess();
    if (Req->Write) {
        status = MmCopyVirtualMemory(ClientProcess, (PVOID)(ULONG_PTR)Req->Buffer, TargetProcess,
            (PVOID)(ULONG_PTR)Req->Address, Req->Size, KernelMode, &bytesCopied);
    } else {
        status = MmCopyVirtualMemory(TargetProcess, (PVOID)(ULONG_PTR)Req->Address, ClientProcess,
            (PVOID)(ULONG_PTR)Req->Buffer, Req->Size, KernelMode, &bytesCopied);
    }
    if (TargetProcess) {
        ObDereferenceObject(TargetProcess);
    }
    return status;
}

NTSTATUS HandleBulk(PBULK_REQUEST BulkReq) {
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    if (!BulkReq || BulkReq->Count == 0 || BulkReq->Count > MAX_BULK_OPERATIONS) {
        return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < BulkReq->Count; i++) {
        BulkReq->Operations[i].Status = ReadWriteMemory(&BulkReq->Operations[i]);
        if (!NT_SUCCESS(BulkReq->Operations[i].Status) && NT_SUCCESS(status)) {
            status = BulkReq->Operations[i].Status;
        }
    }
    return status;
}

NTSTATUS HandleProcessList(PPROC_LIST_REQUEST Req, size_t BufferLength) {
    ULONG capacity;
    ULONG systemInfoLength;
    PVOID systemInfo;
    ULONG needed;
    NTSTATUS status;
    PSYSTEM_PROCESS_INFO current;
    ULONG returned;
    if (!Req || Req->Count == 0 || Req->Count > MAX_PROCESS_LIST_CAPACITY)
        return STATUS_INVALID_PARAMETER;
    capacity = Req->Count;
    if (sizeof(PROC_LIST_REQUEST) + (capacity - 1) * sizeof(PROC_ENTRY) > BufferLength)
        return STATUS_BUFFER_TOO_SMALL;
    systemInfoLength = 256 * 1024;
    systemInfo = NULL;
    needed = 0;
    status = STATUS_INFO_LENGTH_MISMATCH;
    while (systemInfoLength <= 8 * 1024 * 1024) {
        systemInfo = ExAllocatePoolWithTag(NonPagedPool, systemInfoLength, 'nBlA');
        if (!systemInfo)
            return STATUS_INSUFFICIENT_RESOURCES;
        status = ZwQuerySystemInformation(SystemProcessInformation, systemInfo, systemInfoLength, &needed);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(systemInfo, 'nBlA');
            systemInfo = NULL;
            systemInfoLength = needed > systemInfoLength ? needed : systemInfoLength * 2;
            continue;
        }
        break;
    }
    if (!NT_SUCCESS(status)) {
        if (systemInfo)
            ExFreePoolWithTag(systemInfo, 'nBlA');
        return status;
    }
    returned = 0;
    current = (PSYSTEM_PROCESS_INFO)systemInfo;
    for (;;) {
        if (returned < capacity && current->ImageName.Buffer && current->ImageName.Length > 0) {
            PPROC_ENTRY entry = &Req->Processes[returned];
            ULONG copyLength = current->ImageName.Length;
            if (copyLength > (MAX_PROCESS_NAME_LENGTH - 1) * sizeof(WCHAR))
                copyLength = (MAX_PROCESS_NAME_LENGTH - 1) * sizeof(WCHAR);
            entry->ProcessId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
            RtlCopyMemory(entry->Name, current->ImageName.Buffer, copyLength);
            entry->Name[copyLength / sizeof(WCHAR)] = L'\0';
            returned++;
        }
        if (current->NextEntryOffset == 0)
            break;
        current = (PSYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
    }
    ExFreePoolWithTag(systemInfo, 'nBlA');
    Req->Count = returned;
    return STATUS_SUCCESS;
}

NTSTATUS HandleRegionQuery(PREGION_REQUEST Req, size_t BufferLength) {
    PEPROCESS targetProcess;
    HANDLE hProcess;
    NTSTATUS status;
    ULONG64 address;
    ULONG returned;
    if (!Req || Req->Count == 0 || Req->Count > MAX_REGION_LIST_CAPACITY)
        return STATUS_INVALID_PARAMETER;
    if (sizeof(REGION_REQUEST) + (Req->Count - 1) * sizeof(REGION_INFO) > BufferLength)
        return STATUS_BUFFER_TOO_SMALL;
    targetProcess = NULL;
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status))
        return status;
    hProcess = NULL;
    status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_INFORMATION,
        *PsProcessType, KernelMode, &hProcess);
    ObDereferenceObject(targetProcess);
    if (!NT_SUCCESS(status))
        return status;
    returned = 0;
    address = Req->StartAddress ? Req->StartAddress : 0x10000;
    while (returned < Req->Count) {
        MEMORY_BASIC_INFORMATION info;
        SIZE_T returnedLength;
        ULONG64 next;
        RtlZeroMemory(&info, sizeof(info));
        returnedLength = 0;
        status = ZwQueryVirtualMemory(
            hProcess, (PVOID)address, MemoryBasicInformation, &info, sizeof(info), &returnedLength);
        if (!NT_SUCCESS(status))
            break;
        if (info.RegionSize == 0)
            break;
        Req->Regions[returned].BaseAddress = (ULONG64)(ULONG_PTR)info.BaseAddress;
        Req->Regions[returned].RegionSize = info.RegionSize;
        Req->Regions[returned].State = info.State;
        Req->Regions[returned].Protect = info.Protect;
        Req->Regions[returned].Type = info.Type;
        returned++;
        next = (ULONG64)(ULONG_PTR)info.BaseAddress + info.RegionSize;
        if (next <= address)
            break;
        address = next;
    }
    ZwClose(hProcess);
    Req->Count = returned;
    return returned > 0 ? STATUS_SUCCESS : status;
}

NTSTATUS HandleThreadList(PTHREAD_LIST_REQUEST Req, size_t BufferLength) {
    ULONG systemInfoLength;
    PVOID systemInfo;
    ULONG needed;
    NTSTATUS status;
    PSYSTEM_PROCESS_INFO current;
    ULONG returned;
    if (!Req || Req->Count == 0 || Req->Count > MAX_THREAD_LIST_CAPACITY)
        return STATUS_INVALID_PARAMETER;
    if (sizeof(THREAD_LIST_REQUEST) + (Req->Count - 1) * sizeof(THREAD_INFO) > BufferLength)
        return STATUS_BUFFER_TOO_SMALL;
    systemInfoLength = 256 * 1024;
    systemInfo = NULL;
    needed = 0;
    status = STATUS_INFO_LENGTH_MISMATCH;
    while (systemInfoLength <= 8 * 1024 * 1024) {
        systemInfo = ExAllocatePoolWithTag(NonPagedPool, systemInfoLength, 'nBlA');
        if (!systemInfo)
            return STATUS_INSUFFICIENT_RESOURCES;
        status = ZwQuerySystemInformation(SystemProcessInformation, systemInfo, systemInfoLength, &needed);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(systemInfo, 'nBlA');
            systemInfo = NULL;
            systemInfoLength = needed > systemInfoLength ? needed : systemInfoLength * 2;
            continue;
        }
        break;
    }
    if (!NT_SUCCESS(status)) {
        if (systemInfo)
            ExFreePoolWithTag(systemInfo, 'nBlA');
        return status;
    }
    returned = 0;
    current = (PSYSTEM_PROCESS_INFO)systemInfo;
    for (;;) {
        if ((ULONG)(ULONG_PTR)current->UniqueProcessId == Req->ProcessId && returned < Req->Count) {
            PSYSTEM_THREAD_INFO thread = (PSYSTEM_THREAD_INFO)((PUCHAR)current + sizeof(SYSTEM_PROCESS_INFO));
            ULONG i;
            for (i = 0; i < current->NumberOfThreads && returned < Req->Count; i++) {
                HANDLE threadId = thread[i].ClientId.UniqueThread;
                PETHREAD pThread;
                HANDLE hThread;
                THREAD_BASIC_INFO basic;
                if (!threadId)
                    continue;
                pThread = NULL;
                if (!NT_SUCCESS(PsLookupThreadByThreadId(threadId, &pThread)))
                    continue;
                hThread = NULL;
                status = ObOpenObjectByPointer(pThread, OBJ_KERNEL_HANDLE, NULL, THREAD_QUERY_INFORMATION,
                    *PsThreadType, KernelMode, &hThread);
                ObDereferenceObject(pThread);
                if (!NT_SUCCESS(status))
                    continue;
                RtlZeroMemory(&basic, sizeof(basic));
                status =
                    ZwQueryInformationThread(hThread, ThreadBasicInformation, &basic, sizeof(basic), NULL);
                ZwClose(hThread);
                if (!NT_SUCCESS(status) || !basic.TebBaseAddress)
                    continue;
                Req->Threads[returned].ThreadId = (ULONG)(ULONG_PTR)threadId;
                Req->Threads[returned].TebBaseAddress = (ULONG64)(ULONG_PTR)basic.TebBaseAddress;
                returned++;
            }
        }
        if (current->NextEntryOffset == 0)
            break;
        current = (PSYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
    }
    ExFreePoolWithTag(systemInfo, 'nBlA');
    Req->Count = returned;
    return STATUS_SUCCESS;
}

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    size_t inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytesReturned = 0;
    if (inputLength < sizeof(RW_REQUEST)) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto complete;
    }
    switch (ioctl) {
    case IOCTL_READ:
    case IOCTL_WRITE: {
        PRW_REQUEST req = (PRW_REQUEST)buffer;
        req->Write = (ioctl == IOCTL_WRITE);
        req->Status = ReadWriteMemory(req);
        bytesReturned = sizeof(RW_REQUEST);
        break;
    }
    case IOCTL_BULK: {
        PBULK_REQUEST bulkReq = (PBULK_REQUEST)buffer;
        if (inputLength < sizeof(BULK_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = HandleBulk(bulkReq);
        bytesReturned = inputLength;
        break;
    }
    case IOCTL_PROCESSES: {
        PPROC_LIST_REQUEST processReq = (PPROC_LIST_REQUEST)buffer;
        if (inputLength < sizeof(PROC_LIST_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = HandleProcessList(processReq, inputLength);
        bytesReturned = inputLength;
        break;
    }
    case IOCTL_REGIONS: {
        PREGION_REQUEST regionReq = (PREGION_REQUEST)buffer;
        if (inputLength < sizeof(REGION_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = HandleRegionQuery(regionReq, inputLength);
        bytesReturned = inputLength;
        break;
    }
    case IOCTL_THREADS: {
        PTHREAD_LIST_REQUEST threadReq = (PTHREAD_LIST_REQUEST)buffer;
        if (inputLength < sizeof(THREAD_LIST_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = HandleThreadList(threadReq, inputLength);
        bytesReturned = inputLength;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
complete:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLink;
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symbolicLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDeviceSecure(
        DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &sddl, NULL, &deviceObject);
    if (!NT_SUCCESS(status))
        return status;
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_NAME);
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
