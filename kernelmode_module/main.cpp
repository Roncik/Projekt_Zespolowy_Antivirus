#include "pch.h"
#include "DeviceControl.hpp"

#define DEVICE_NAME     L"\\Device\\OpenAV"
#define SYMBOLIC_NAME   L"\\DosDevices\\OpenAV"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
DRIVER_UNLOAD DriverUnload;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName, symName;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symName, SYMBOLIC_NAME);

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) 
    {
        KdPrint(("IoCreateDevice failed: 0x%X\n", status));
        return status;
    }

    status = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(status)) 
    {
        KdPrint(("IoCreateSymbolicLink failed: 0x%X\n", status));
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceControl::DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceControl::DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl::DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // device initialized
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    KdPrint(("Driver loaded\n"));
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symName;
    RtlInitUnicodeString(&symName, SYMBOLIC_NAME);

    IoDeleteSymbolicLink(&symName);
    IoDeleteDevice(DriverObject->DeviceObject);
    KdPrint(("Driver unloaded\n"));
}

