#pragma once
class ProcessManager
{
public:
    struct ProcessInfo
    {
        HANDLE processID;
        HANDLE parentProcessID;
        std::wstring processName;
    };

    struct SystemModuleInfo
    {
        std::wstring fileName;
        std::wstring filePath;
    };

    static bool GetMainModuleBase(DWORD pid, uintptr_t& outBase, std::wstring& outPath);

    static bool GetProcessImagePath(DWORD pid, std::wstring& outPath);

    bool GetProcessOwner(DWORD pid, std::wstring& outDomain, std::wstring& outUser);

    std::wstring DevicePathToDosPath(const std::wstring& devicePath);

    bool IsExecuteProtection(DWORD prot);

    bool IsWritableExecutable(DWORD prot);

    static bool GetAllProcesses(std::vector<ProcessInfo>& processes);

    bool GetAllSystemModules(std::vector<SystemModuleInfo>& systemModules);
};

