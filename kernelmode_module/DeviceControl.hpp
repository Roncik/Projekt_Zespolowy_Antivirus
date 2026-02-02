#pragma once

// przykładowy IOCTL
#define IOCTL_MY_ECHO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

class DeviceControl
{
public:
	static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
};