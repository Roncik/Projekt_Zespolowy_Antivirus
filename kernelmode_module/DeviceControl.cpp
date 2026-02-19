#include "pch.h"
#include "DeviceControl.hpp"
#include "IntegrityChecker.h"

NTSTATUS DeviceControl::DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl::DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION  stack;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    PVOID buffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = Irp->AssociatedIrp.SystemBuffer; // METHOD_BUFFERED

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {

    case IOCTL_MY_ECHO:
    {
        // echo: zwróć użytkownikowi to co przysłał
        ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG copyLen = min(inLen, outLen);

        if (copyLen > 0 && buffer != NULL)
        {
            // buffer jest w kernelu (SYSTEM_BUFFER) - można użyć RtlCopyMemory
            RtlCopyMemory(buffer, buffer, copyLen); // proste echo (buffer już zawiera dane)
            info = copyLen;
            status = STATUS_SUCCESS;
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }
    case IOCTL_KERNEL_INTEGRITY_SCAN:
    {
        // 1. Run the Scan (Synchronous)
        IntegrityChecker::ClearResults();
        IntegrityChecker::ScanAllKernelModules(); // This populates the Linked List

        // 2. Calculate Required Size
        ExAcquireFastMutex(&IntegrityChecker::ResultMutex);
        ULONG requiredSize = sizeof(IntegrityChecker::SCAN_RESULTS_HEADER) + (IntegrityChecker::ResultCount * sizeof(IntegrityChecker::Code_Patch));

        // 3. Check User Buffer Size
        ULONG outputBufferLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (outputBufferLen < requiredSize) 
        {
            // Buffer too small? Tell user how much we need.
            status = STATUS_BUFFER_OVERFLOW; // Warning: Buffer too small
            info = sizeof(ULONG); // Return at least the count so they know

            // If they gave us at least enough for the header, write the count
            if (outputBufferLen >= sizeof(IntegrityChecker::SCAN_RESULTS_HEADER)) 
            {
                IntegrityChecker::PSCAN_RESULTS_HEADER header = (IntegrityChecker::PSCAN_RESULTS_HEADER)Irp->AssociatedIrp.SystemBuffer;
                header->Count = IntegrityChecker::ResultCount; // Tell them how many items exist
            }
        }
        else 
        {
            // 4. Buffer is Big Enough - Copy Data
            IntegrityChecker::PSCAN_RESULTS_HEADER header = (IntegrityChecker::PSCAN_RESULTS_HEADER)Irp->AssociatedIrp.SystemBuffer;
            header->Count = IntegrityChecker::ResultCount;

            IntegrityChecker::PCode_Patch pDest = (IntegrityChecker::PCode_Patch)((PUCHAR)header + sizeof(IntegrityChecker::SCAN_RESULTS_HEADER));
            PLIST_ENTRY pEntry = IntegrityChecker::ResultListHead.Flink;

            while (pEntry != &IntegrityChecker::ResultListHead) 
            {
                IntegrityChecker::PPATCH_NODE node = CONTAINING_RECORD(pEntry, IntegrityChecker::PATCH_NODE, ListEntry);

                // Copy struct
                RtlCopyMemory(pDest, &node->Data, sizeof(IntegrityChecker::Code_Patch));

                pDest++; // Advance pointer
                pEntry = pEntry->Flink;
            }

            info = requiredSize;
            status = STATUS_SUCCESS;
        }
        ExReleaseFastMutex(&IntegrityChecker::ResultMutex);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

