# OpenAV

Windows 11+10 Open source Antivirus

At the current development stage the project is a showcase of methods to detect malware.

Current methods:
- **Verifying integrity of kernelmode and usermode system modules**
- **Performing file scans against a blacklist**
- **VirtusTotal API integration**
- **Scanning processes for blacklisted signatures**
- **Searching for malicious memory tampering in processes and kernel drivers**

This project uses a GUI written using [ImGui](https://github.com/ocornut/imgui) and rendered with Direct3D9.

# How to build

you need:

[DirectX Software Development Kit](https://www.microsoft.com/en-us/download/details.aspx?id=6812)

[Visual Studio](https://visualstudio.microsoft.com/pl/downloads/)

[Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

Compile the entire project using Visual Studio. Executable and driver will be in x64/x86 folder.

# How to run

The OpenAV.exe and OpenAVDriver.sys must be in the same directory.

For the kernel integrity check you must enable TestSign mode via bcdedit: 
- Open CMD as administrator and enter this command: **bcdedit /set testsigning on**
- Restart the system.
- To later disable TestSign mode enter this command: **bcdedit /set testsigning off** and restart the system.

# Documentation

## usermode_module
Main Project that contains the code for the usermode features, GUI and threads synchronization logic.

### - File Scanner (FileScanner::ScanDirectoryAndAllSubdirectories_MD5)
The file scanner works by comparing all files in the file system against a MD5 hash blacklist.

[GetLogicalDrives](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getlogicaldrives) is used to get all volume("logical drive") letters.

[FindFirstFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew), [FindNextFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilew) and stack is used to scan all files in all subdirectories of each volume(on Windows the root of every path for regular files is the volume letter e.g. C:)

### - System process Integrity checker (SystemProcessDefender::DiskMemoryIntegrityCheckSystemProcesses)
This integrity check works by comparing the code loaded in RAM with what is on file.

A mapping of the process's respective file is created in memory using [CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw), then the process's and file's headers are parsed to get offsets/addresses of executable sections to later compare those byte-by-byte in search of inconsistencies. At this step the found inconsistencies must be filtered since mechanisms like relocations would cause false-positives; inconsistencies smaller than 12 bytes are ignored(12 bytes is the smallest size for a trivial code detour on 64bit).

### - Signature Scanner (SystemProcessDefender::ScanAllProcessesForBlacklistedSignatures)
Scans all running processes for blacklisted code signatures.

The running processes are enumerated using [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)(it needs to be dynamically imported from ntdll.dll).

[VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex) is used to iterate address space and find executable memory regions. Each executable region is read using [ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory) into a buffer which is then checked for blacklisted signatures.

### - VirusTotal Scanner (VirusTotalManager::ScanRunningProcessesAndDrivers)
Scans all running processes and drivers using VirusTotal API.

Running processes and drivers are enumerated using [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation).

Each is then sent for analysis via VirusTotal API. A local database of already scanned files is saved to hashdb.txt in format md5hash;result.

## kernelmode_module
Project for the driver, contains code for the kernel integrity check and communication with the usermode.

### - Kernel integrity check (IntegrityChecker::ScanAllKernelModules)
This integrity check works by comparing the code loaded in RAM with what is on file.

[AuxKlibQueryModuleInformation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/aux_klib/nf-aux_klib-auxklibquerymoduleinformation) is used to enumerate all loaded kernel modules.

Each kernel module's file is mapped into memory buffer using [ZwReadFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwreadfile), then the headers are parsed for both the file mapping and the loaded driver to get the offsets/addresses of executable sections, then the executable sections are compared byte-by-byte. All mismatches smaller than 12 bytes are ignored(12 bytes is the smallest size for a trivial code detour on 64bit), all pagewx sections are also skipped as those are created for the Microsoft's [Warbird system](https://en.wikipedia.org/wiki/Microsoft_Warbird) and checking those would cause lots of false-positives.




