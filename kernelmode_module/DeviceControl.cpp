#include "pch.h"
#include "DeviceControl.hpp"

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
    }
    break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

