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

    bool GetMainModuleBase(DWORD pid, uintptr_t& outBase, std::wstring& outPath);

    bool GetProcessImagePath(DWORD pid, std::wstring& outPath);

    bool GetProcessOwner(DWORD pid, std::wstring& outDomain, std::wstring& outUser);

    std::wstring DevicePathToDosPath(const std::wstring& devicePath);

    bool IsExecuteProtection(DWORD prot);

    bool IsWritableExecutable(DWORD prot);

    bool GetAllProcesses(std::vector<ProcessInfo>& processes);
};

