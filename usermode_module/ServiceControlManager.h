#pragma once

#define ERROR_SERVICE_ALREADY_EXISTS 1001L

class ServiceControlManager
{
private:
    struct ScHandle
    {
        SC_HANDLE h;
        ScHandle(SC_HANDLE _h = nullptr) : h(_h) {}
        ~ScHandle()
        {
            if (h) 
                CloseServiceHandle(h);
        }
        operator SC_HANDLE() const
        {
            return h;
        }

        bool valid() const
        {
            return h != nullptr;
        }
    };
    
    static const DWORD DEFAULT_WAIT_MS = 10000;
    inline static const std::wstring serviceName = L"OpenAV";
    inline static std::wstring driverPath = L"./OpenAVDriver.sys";

    typedef DWORD SC_RESULT;

    static SC_RESULT WaitForServiceStatus(SC_HANDLE schService, DWORD desiredState, DWORD timeoutMs = DEFAULT_WAIT_MS);

    static SC_RESULT EnsureDriverServiceExists(const std::wstring& serviceName, const std::wstring& binaryPath);

    static SC_RESULT StartDriverService(const std::wstring& serviceName, DWORD waitMs = DEFAULT_WAIT_MS);

    static SC_RESULT IsDriverServiceRunning(const std::wstring& serviceName, bool& outIsRunning);

    static SC_RESULT StopDriverService(const std::wstring& serviceName, DWORD waitMs = DEFAULT_WAIT_MS);

    static SC_RESULT DeleteDriverService(const std::wstring& serviceName);

public:
    static bool CreateAndStartDriver(const std::wstring& serviceName = serviceName, const std::wstring& driverPath = driverPath);
    static bool SetDriverPath(const std::wstring& driverPath);
};

//// Przykładowy main pokazujący użycie
//int wmain(int argc, wchar_t* argv[])
//{
//    // Przykład wywołania:
//    // DRIVER_NAME i path do pliku .sys
//    std::wstring serviceName = L"MyDriver";
//    std::wstring binaryPath = L"C:\\Windows\\System32\\drivers\\MyDriver.sys";
//
//    DWORD rc;
//
//    rc = EnsureDriverServiceExists(serviceName, binaryPath);
//    if (rc != ERROR_SUCCESS) {
//        std::wcerr << L"EnsureDriverServiceExists failed: " << rc << L"\n";
//        return 1;
//    }
//    std::wcout << L"Service ensured/created.\n";
//
//    rc = StartDriverService(serviceName);
//    if (rc != ERROR_SUCCESS) {
//        std::wcerr << L"StartDriverService failed: " << rc << L"\n";
//    }
//    else {
//        std::wcout << L"Service started.\n";
//    }
//
//    bool running = false;
//    rc = IsDriverServiceRunning(serviceName, running);
//    if (rc == ERROR_SUCCESS) {
//        std::wcout << L"Is running: " << (running ? L"YES" : L"NO") << L"\n";
//    }
//    else {
//        std::wcerr << L"IsDriverServiceRunning failed: " << rc << L"\n";
//    }
//
//    // stop
//    rc = StopDriverService(serviceName);
//    if (rc != ERROR_SUCCESS) {
//        std::wcerr << L"StopDriverService failed: " << rc << L"\n";
//    }
//    else {
//        std::wcout << L"Service stopped.\n";
//    }
//
//    // delete
//    rc = DeleteDriverService(serviceName);
//    if (rc != ERROR_SUCCESS) {
//        std::wcerr << L"DeleteDriverService failed: " << rc << L"\n";
//    }
//    else {
//        std::wcout << L"Service deleted.\n";
//    }
//
//    return 0;
//}


