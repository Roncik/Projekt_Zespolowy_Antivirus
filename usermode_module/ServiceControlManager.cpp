#include "pch.h"
#include "ServiceControlManager.h"

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
        return GetLastError();

    ScHandle sch(OpenServiceW(scm, serviceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS));
    if (!sch.valid())
        return GetLastError();

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
bool ServiceControlManager::CreateAndStartDriver(const std::wstring& serviceName, const std::wstring& driverPath)
{
    if (ServiceControlManager::EnsureDriverServiceExists(serviceName, driverPath) != ERROR_SUCCESS)
        return false;
    if (ServiceControlManager::StartDriverService(serviceName) != ERROR_SUCCESS)
        return false;



    return true;
}

bool ServiceControlManager::SetDriverPath(const std::wstring& driverPath)
{
    // check whether a file at the given path exists and we have access to it
    std::ifstream file(driverPath);
    if (!file)
        return false;
    file.close();

    ServiceControlManager::driverPath = driverPath;

    return true;
}
