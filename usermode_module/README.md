# Project for the usermode functionalities of the antivirus software

## External Dependencies

This project uses Direct3D9 for the Graphical User Interface so you need:

[DirectX Software Development Kit](https://www.microsoft.com/en-us/download/details.aspx?id=6812)

[DirectX End-User Runtimes](https://www.microsoft.com/en-us/download/details.aspx?id=8109)

## 3.1 FileScanner

### FileScanner Class
Provides methods:
- **LoadBlacklist_MD5** - loads MD5 hashes into memory from a file(hexstring32 each line).
- **ScanAllDirectories_MD5** - scans files in all drives installed in the system and all their subdirectories against a previously loaded MD5 blacklist.
- **ScanDirectoryAndAllSubdirectories_MD5** - scans files in a given directory and all its subdirectories against a previously loaded MD5 blacklist.

### MD5_HashManager Class
Provides methods for managing the MD5 databases and computing file's MD5 hash.

## 3.2 SystemProcessDefender

### SystemProcessDefender Class
Provides methods:
- **VerifyEmbeddedSignature** - checks the validity of the digital signature of a file given its path.
- **GetSystem32Processes** - find all running executables at System32 path and separate them into 'SYSTEM' owned and owned by other users.
- **CompareImageSectionsWithDisk** - verifies the integrity of the original code sections of a process loaded in memory by comparing them with their version on-file.
- **ScanExecutableMemoryForSignatures** - scans the executable memory of a process for matches with a given code signatures list.
- **CheckThreadsExecution** - scans process's running threads for execution of code outside of original executable regions.
- **FindSuspiciousExecutableAllocations** - scans process's memory regions for ones that were manually allocated and are executable.(UNUSED)

### ProcessManager Class
Provides methods:
- **GetMainModuleBase** - given a PID(processID) finds the main module's base address in memory and the path to the main module(.exe) on disk.
- **GetProcessImagePath** - given a PID finds the path of the main module on disk. Unlike previous method it uses QueryFullProcessImageNameW.
- **GetProcessOwner** - given a PID finds the user and domain assigned to the process.
- **DevicePathToDosPath** - converts device path to DOS path.
- **IsExecuteProtection, IsWritableExecutable** - checks page protection mask properties.
- **GetAllProcesses** - uses NtQuerySystemInformation to enumerate all running processes in the system.
- **GetAllSystemModules** - uses NtQuerySystemInformation to enumerate all loaded system modules.

### PrivilegeManager Class
Provides method for enabling debug privilege on current process

### SignatureManager Class
Provides functions for parsing code signatures and finding signatures in a given byte buffer.

## 3.11 VirusTotal

### VirusTotalManager Class
Provides methods for analysing files using the VirusTotal api(via https requests)

### HTTPSManager Class
Provides methods for sending HTTPS requests using windows's WINHTTP library

## ImGUIManager Class
Contains static members for the Direct3D9 such as device and parameters for later use by GUI.

Provides methods:
- **CreateDeviceD3D** - Creates a Direct3D9 device for later use.
- **CleanupDeviceD3D** - Clear the D3D9 device.
- **ResetDevice** - Reset the D3D9 device.
- **WndProc** - Callback for handling messages sent to the GUI window. Tries ImGUI callback first, if it fails it falls back to default handler.

## LogsManager Class
Provides the Log struct and the following methods:

- **Log** - Saves a log to a global logs list and to file.
- **ExportLogToFile** - Saves the log to file
- **ReadLogsFromFile** - Reads logs from file into memory

## ServiceControlManager
Provides methods for controlling the OpenAV driver - creating, starting, stopping, deleting, communication

- **WaitForServiceStatus** - Helper function that awaits service status update via Windows ServiceController.
- **EnsureDriverServiceExists** - If the driver's service doesn't exist this creates one, if it does exist this updates the existing one.
- **StartDriverService** - Starts the driver's registered service.
- **IsDriverServiceRunning** - Helper function for checking driver's service status.
- **StopDriverService** - Stops the driver's registered service.
- **DeleteDriverService** - Deletes the driver's registered service.
- **CreateAndStartDriver** - Wrapper for registering the service and starting the driver.
- **StopDriverAndDeleteService** - Wrapper for stopping the driver and deleting the service.
- **IntegrityCheckKernel** - Calls the driver's Kernel Integrity Check function and retrieves the result.
