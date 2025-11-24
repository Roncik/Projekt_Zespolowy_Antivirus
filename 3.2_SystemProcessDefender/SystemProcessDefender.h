#pragma once

class SystemProcessDefender
{
public:
    struct ProcessInfo
    {
        DWORD pid;
        std::wstring path;
        std::wstring domain;
        std::wstring user;
    };
    
    bool VerifyEmbeddedSignature(const std::wstring& filePath);
    
    bool GetProcessImagePath(DWORD pid, std::wstring& outPath);
    
    bool GetProcessOwner(DWORD pid, std::wstring& outDomain, std::wstring& outUser);

    void GetSystem32Processes(std::vector<ProcessInfo>& systemProcesses, std::vector<ProcessInfo>& nonSystemSystem32Processes);
};

