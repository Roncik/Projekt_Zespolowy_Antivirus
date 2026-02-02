#pragma once

#define ERROR_SERVICE_ALREADY_EXISTS 1001L

// IOCTL codes (must be exactly the same as in kernelmode_module)
#define IOCTL_MY_ECHO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
    inline static const std::wstring deviceName = L"OpenAV";
    inline static const std::wstring serviceName = L"OpenAV";
    inline static std::wstring driverFileName = L"OpenAVDriver.sys";

    typedef DWORD SC_RESULT;

    static SC_RESULT WaitForServiceStatus(SC_HANDLE schService, DWORD desiredState, DWORD timeoutMs = DEFAULT_WAIT_MS);

    static SC_RESULT EnsureDriverServiceExists(const std::wstring& serviceName, const std::wstring& binaryPath);

    static SC_RESULT StartDriverService(const std::wstring& serviceName, DWORD waitMs = DEFAULT_WAIT_MS);

    static SC_RESULT IsDriverServiceRunning(const std::wstring& serviceName, bool& outIsRunning);

    static SC_RESULT StopDriverService(const std::wstring& serviceName, DWORD waitMs = DEFAULT_WAIT_MS);

    static SC_RESULT DeleteDriverService(const std::wstring& serviceName);

public:
    static bool CreateAndStartDriver(const std::wstring& serviceName = serviceName, const std::wstring& driverFileName = driverFileName);
    static bool StopDriverAndDeleteService(const std::wstring& serviceName = serviceName);
    static bool ExampleIOCTLCall(const std::wstring& deviceName = deviceName);
};


