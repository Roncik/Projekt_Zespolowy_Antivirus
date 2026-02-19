#include "pch.h"
#include "ServiceControlManager.h"
#include "LogsManager.h"
#include "ImGUIManager.h"

// Awaits service status change to desired with timeout
DWORD ServiceControlManager::WaitForServiceStatus(SC_HANDLE schService, DWORD desiredState, DWORD timeoutMs)
{
    if (!schService) return ERROR_INVALID_HANDLE;

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    ULONGLONG start = GetTickCount64();
    while (true) {
        if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded))
        {
            return GetLastError();
        }

        if (ssp.dwCurrentState == desiredState) return ERROR_SUCCESS;

        if (GetTickCount64() - start > timeoutMs) return ERROR_TIMEOUT;

        // await minimal interval
        DWORD wait = ssp.dwWaitHint / 10;
        if (wait < 200) wait = 200;
        if (wait > 2000) wait = 2000;
        Sleep(wait);
    }
}

// Creates a service for the driver if it doesn't exist, otherwise it tries to update the existing service if it has different params
DWORD ServiceControlManager::EnsureDriverServiceExists(const std::wstring& serviceName, const std::wstring& binaryPath)
{
    DWORD err = ERROR_SUCCESS;
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
    if (!scm.valid()) return GetLastError();

    // try opening a service(maybe it already exists)
    ScHandle sch(OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START));
    if (!sch.valid())
    {
        // service doesn't exists - create one
        SC_HANDLE hNew = CreateServiceW(
            scm,
            serviceName.c_str(),           // service name
            serviceName.c_str(),           // display name
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,         // type
            SERVICE_DEMAND_START,          // start on demand
            SERVICE_ERROR_NORMAL,          // error control
            binaryPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr
        );
        if (!hNew)
        {
            return GetLastError();
        }
        CloseServiceHandle(hNew);
        return ERROR_SUCCESS;
    }

    // service already exists, check its binpath
    DWORD bytesNeeded = 0;
    QueryServiceConfigW(sch, nullptr, 0, &bytesNeeded); // get needed buffer size
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER && bytesNeeded == 0)
    {
        return GetLastError();
    }

    std::vector<BYTE> buffer(bytesNeeded);
    LPQUERY_SERVICE_CONFIGW pConfig = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
    if (!QueryServiceConfigW(sch, pConfig, bytesNeeded, &bytesNeeded))
    {
        return GetLastError();
    }

    std::wstring existingPath = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"";
    if (existingPath != binaryPath)
    {
        // spróbuj zaktualizować ścieżkę binarną
        if (!ChangeServiceConfigW(
            sch,
            SERVICE_KERNEL_DRIVER,    // type unchanged
            SERVICE_NO_CHANGE,        // start type unchanged
            SERVICE_NO_CHANGE,        // error control unchanged
            binaryPath.c_str(),       // new path
            nullptr, nullptr, nullptr,
            nullptr, nullptr,
            serviceName.c_str()))     // new name
        {
            return GetLastError();
        }
    }

    return ERROR_SUCCESS;
}

// Start the service with the given serviceName and wait until the status updates to RUNNING
DWORD ServiceControlManager::StartDriverService(const std::wstring& serviceName, DWORD waitMs)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid())
    {
        return GetLastError();
    }

    ScHandle sch(OpenServiceW(scm, serviceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS));
    if (!sch.valid())
    {
        return GetLastError();
    }

    // StartService returns false if the service is already started
    if (!StartServiceW(sch, 0, nullptr)) 
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING && err != ERROR_SERVICE_ALREADY_EXISTS && err != ERROR_SUCCESS) 
        {
            return err;
        }
    }

    // wait till status updates to RUNNING or timeouts
    return WaitForServiceStatus(sch, SERVICE_RUNNING, waitMs);
}

// Check service status (STATUS == RUNNING)
DWORD ServiceControlManager::IsDriverServiceRunning(const std::wstring& serviceName, bool& outIsRunning)
{
    outIsRunning = false;
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) 
        return GetLastError();

    ScHandle sch(OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS));
    if (!sch.valid()) 
        return GetLastError();

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(sch, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded)) 
    {
        return GetLastError();
    }

    outIsRunning = (ssp.dwCurrentState == SERVICE_RUNNING);
    return ERROR_SUCCESS;
}

// Stop the service, waits for the status to update with timeout
DWORD ServiceControlManager::StopDriverService(const std::wstring& serviceName, DWORD waitMs)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) 
        return GetLastError();

    ScHandle sch(OpenServiceW(scm, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!sch.valid()) 
        return GetLastError();

    SERVICE_STATUS status = {};
    if (!ControlService(sch, SERVICE_CONTROL_STOP, &status)) 
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE) 
            return err;
    }

    // wait till status updates to STOPPED or timeouts
    return WaitForServiceStatus(sch, SERVICE_STOPPED, waitMs);
}

// Delete service. Service must be stopped beforehand, this function doesn't handle that
DWORD ServiceControlManager::DeleteDriverService(const std::wstring& serviceName)
{
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) 
        return GetLastError();

    ScHandle sch(OpenServiceW(scm, serviceName.c_str(), DELETE));
    if (!sch.valid()) 
        return GetLastError();

    if (!DeleteService(sch)) {
        return GetLastError();
    }

    return ERROR_SUCCESS;
}

// Wrapper for starting the driver via SC
bool ServiceControlManager::CreateAndStartDriver(const std::wstring& serviceName, const std::wstring& driverFileName)
{
    // We need to pass full driver path to SC. We assume the driver file is always in the same directory as .exe
    auto getCurrentDirPath = []() -> std::wstring
        {
            WCHAR buffer[MAX_PATH] = { 0 };
            GetModuleFileNameW(NULL, buffer, MAX_PATH);
            std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
            return std::wstring(buffer).substr(0, pos);
        };
    std::wstring driverFullPath = getCurrentDirPath() + L"\\" + driverFileName;
    
    
    if (ServiceControlManager::EnsureDriverServiceExists(serviceName, driverFullPath) != ERROR_SUCCESS)
    {
        std::wcout << L"Creating and starting driver failed!" << std::endl;
        return false;
    }

    if (ServiceControlManager::StartDriverService(serviceName) != ERROR_SUCCESS)
    {
        std::wcout << L"Creating and starting driver failed!" << std::endl;
        return false;
    }

    return true;
}

// Wrapper for stopping the driver and deleting its service
bool ServiceControlManager::StopDriverAndDeleteService(const std::wstring& serviceName)
{
    ServiceControlManager::StopDriverService(serviceName);
    
    if (ServiceControlManager::DeleteDriverService(serviceName) != ERROR_SUCCESS)
        return false;
    
    return true;
}

bool ServiceControlManager::ExampleIOCTLCall(const std::wstring& deviceName)
{
    std::wstring devicePath = L"\\\\.\\" + deviceName;
    
    // To send IOCTL requests we need to open a R/W handle to the device
    HANDLE hDevice = CreateFileW(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
        return false;
    }

    char inbuf[] = "Hello from usermode";
    char outbuf[256] = { 0 };
    DWORD bytes = 0;

    BOOL ok = DeviceIoControl(hDevice, IOCTL_MY_ECHO, inbuf, (DWORD)strlen(inbuf) + 1, outbuf, sizeof(outbuf), &bytes, NULL);
    if (!ok)
    {
        CloseHandle(hDevice);
        return false;
    }
    else 
        printf("Driver replied (%u bytes): '%s'\n", bytes, outbuf);
    
    CloseHandle(hDevice);
    return true;
}

bool ServiceControlManager::IntegrityCheckKernel(const std::wstring& deviceName)
{
    std::wstring devicePath = L"\\\\.\\" + deviceName;

    // To send IOCTL requests we need to open a R/W handle to the device
    HANDLE hDevice = CreateFileW(devicePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hDevice);
        return false;
    }

    // 1. First Call: Get the required size (Buffer Overflow expected)
    DWORD bytesReturned = 0;
    SCAN_RESULTS_HEADER dummyHeader = { 0 };

    // We pass a small buffer just to get the 'Count' back
    BOOL result = DeviceIoControl(hDevice, IOCTL_KERNEL_INTEGRITY_SCAN, NULL, 0, &dummyHeader, sizeof(dummyHeader), &bytesReturned, NULL);

    // The driver returns STATUS_BUFFER_OVERFLOW (which maps to False/GetLastError usually) if it has data but buffer is small
    // But we check the dummyHeader.Count to see if anything was found.

    if (dummyHeader.Count == 0) 
    {
        std::cout << "[*] No patches detected." << std::endl;
        CloseHandle(hDevice);
        return true;
    }

    std::cout << "[*] Detected " << dummyHeader.Count << " potential patches. Allocating buffer..." << std::endl;

    // 2. Allocate correct size
    ULONG bufferSize = sizeof(SCAN_RESULTS_HEADER) + (dummyHeader.Count * sizeof(Code_Patch));
    std::vector<BYTE> buffer(bufferSize);

    // 3. Second Call: Retrieve actual data
    result = DeviceIoControl(hDevice, IOCTL_KERNEL_INTEGRITY_SCAN, NULL, 0, buffer.data(), bufferSize, &bytesReturned, NULL);

    if (!result)
    {
        std::cerr << "Failed to retrieve results. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return false;
    }

    // 4. Parse Flat Data into your Pointer Structs
    PSCAN_RESULTS_HEADER pHeader = (PSCAN_RESULTS_HEADER)buffer.data();
    PCode_Patch pEntries = (PCode_Patch)(buffer.data() + sizeof(SCAN_RESULTS_HEADER));

    std::vector<CodePatch_UM> patches;

    for (ULONG i = 0; i < pHeader->Count; i++) 
    {
        CodePatch_UM patch;

        // Point to the strings inside the flat buffer
        // Note: These pointers are valid only as long as 'buffer' exists
        patch.FilePath = pEntries[i].FilePath;
        patch.SectionName = pEntries[i].SectionName;
        patch.RVA = pEntries[i].RVA;
        patch.Length = pEntries[i].Length;

        // Cast raw bytes to char* for your struct
        patch.OriginalBytes = (unsigned char*)pEntries[i].OriginalBytes;
        patch.ActualBytes = (unsigned char*)pEntries[i].ActualBytes;

        patches.push_back(patch);

        LogsManager::log_entry logentry
        {
            .Type = "Kernel Memory Anomaly",
            .Module_name = "Driver",
            .Date = LogsManager::GetCurrentDate(),
            .Location = patch.FilePath,
            .Description = "A code patch was detected in this kernel driver"
        };
        //build extra info
        std::stringstream extrainfoss;
        extrainfoss << "Section: " << patch.SectionName << ". RVA: " << std::hex << patch.RVA << ".Original bytes : ";
        for (int i = 0; i < patch.Length; ++i)
            extrainfoss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << static_cast<int>((unsigned char)patch.OriginalBytes[i]) << " ";
        extrainfoss << ". Actual bytes: ";
        for (int i = 0; i < patch.Length; ++i)
            extrainfoss << std::hex << std::setw(2) << std::setfill('0') << std::uppercase << static_cast<int>((unsigned char)patch.ActualBytes[i]) << " ";
        logentry.Extra_info = extrainfoss.str();

        auto logentryPtr = std::make_unique<LogsManager::log_entry>(logentry);
        ImGUIManager::lQ_mutex.lock();
        ImGUIManager::logQueue.push_back(std::move(logentryPtr));
        ImGUIManager::lQ_mutex.unlock();
    }

    CloseHandle(hDevice);
    return true;
}
