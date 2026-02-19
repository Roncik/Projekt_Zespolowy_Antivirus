# Project for the kernelmode functionalities of the antivirus software

## DeviceControl Class
Provides methods for communication via IOCTL

- **DispatchDeviceControl** - This is the function executed when the driver is called via IOCTL. Handles the request based on the IOCTL code passed.

## IntegrityChecker Class
Provides functionality for checking the integrity of all loaded kernel modules and a linked-list result buffer system.

- **ReadFileFromDisk** - Maps a file from disk into kernel memory.
- **VerifyDriver** - Checks integrity of executable sections of a kernel module by comparing whats loaded in memory with whats on file.
- **ReportPatch** - Adds a scan result to the results linked-list buffer.
- **ClearResults** - Clears the linked-list buffer by sequentially unlinking and deallocating the nodes.
- **ScanAllKernelModules** - Gets all loaded modules via AuxKlib and calls VerifyDriver for each.


