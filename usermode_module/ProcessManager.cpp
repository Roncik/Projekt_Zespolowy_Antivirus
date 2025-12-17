#include "pch.h"
#include "ProcessManager.h"

bool ProcessManager::GetMainModuleBase(DWORD pid, uintptr_t& outBase, std::wstring& outPath)
{
    outBase = 0;
    outPath.clear();
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hsnap == INVALID_HANDLE_VALUE) 
        return false;
    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    bool got = false;
    if (Module32FirstW(hsnap, &me))
    {
        // first module is the main module (.exe)
        outBase = (uintptr_t)me.modBaseAddr;
        outPath = me.szExePath;
        got = true;
    }
    CloseHandle(hsnap);
    return got;
}

bool ProcessManager::GetProcessImagePath(DWORD pid, std::wstring& outPath)
{
    outPath.clear();
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    DWORD capacity = 32768; // Sample buffer
    std::vector<wchar_t> buffer(capacity);
    DWORD size = capacity;
    if (QueryFullProcessImageNameW(hProc, 0, buffer.data(), &size))
    {
        outPath.assign(buffer.data(), size);
        CloseHandle(hProc);
        return true;
    }
    else
    {
        CloseHandle(hProc);
        return false;
    }
}

bool ProcessManager::GetProcessOwner(DWORD pid, std::wstring& outDomain, std::wstring& outUser)
{
    outDomain.clear();
    outUser.clear();

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    {
        CloseHandle(hProc);
        return false;
    }

    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    std::vector<BYTE> tokenInfoBuf(tokenInfoLen);
    if (!GetTokenInformation(hToken, TokenUser, tokenInfoBuf.data(), tokenInfoLen, &tokenInfoLen))
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenInfoBuf.data());
    SID* pSid = reinterpret_cast<SID*>(tokenUser->User.Sid);

    wchar_t name[512];
    wchar_t domain[512];
    DWORD nameLen = _countof(name);
    DWORD domainLen = _countof(domain);
    SID_NAME_USE snu;
    if (!LookupAccountSidW(NULL, pSid, name, &nameLen, domain, &domainLen, &snu))
    {
        CloseHandle(hToken);
        CloseHandle(hProc);
        return false;
    }

    outUser.assign(name, nameLen);
    outDomain.assign(domain, domainLen);

    CloseHandle(hToken);
    CloseHandle(hProc);
    return true;
}

std::wstring ProcessManager::DevicePathToDosPath(const std::wstring& devicePath)
{
    if (devicePath.empty()) return {};

    DWORD len = GetLogicalDriveStringsW(0, NULL);
    if (len == 0) return devicePath;
    std::vector<wchar_t> buf(len + 1);
    GetLogicalDriveStringsW(len + 1, buf.data());

    wchar_t drive[4] = { 0 };
    wchar_t deviceName[MAX_PATH] = { 0 };

    wchar_t* p = buf.data();
    while (*p)
    {
        // p points to "C:\\"
        drive[0] = p[0];
        drive[1] = L':';
        drive[2] = L'\0';
        if (QueryDosDeviceW(drive, deviceName, MAX_PATH))
        {
            std::wstring devName(deviceName);
            // if devicePath starts with devName, replace it with drive letter
            if (_wcsnicmp(devicePath.c_str(), devName.c_str(), devName.length()) == 0)
            {
                std::wstring rest = devicePath.substr(devName.length());
                std::wstring result = std::wstring(drive) + rest;
                return result;
            }
        }
        // advance to next drive string
        while (*p) ++p;
        ++p;
    }
    return devicePath; // fallback
}

bool ProcessManager::IsExecuteProtection(DWORD prot)
{
    // mask out guard/no-cache flags to get base protection
    DWORD base = prot & 0xFF;
    switch (base)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool ProcessManager::IsWritableExecutable(DWORD prot)
{
    // mask out guard/no-cache flags to get base protection
    DWORD base = prot & 0xFF;
    switch (base)
    {
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY: // copy-on-write also podejrzane
        return true;
    default:
        return false;
    }
}

bool ProcessManager::GetAllProcesses(std::vector<ProcessInfo>& processes)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) 
        return false;

    ULONG bufferSize = 1;
    std::vector<BYTE> buffer;
    NTSTATUS status;
    ULONG returnLen = 0;
    
    static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xC0000004L;

    typedef struct _UNICODE_STRING 
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING;

    typedef LONG KPRIORITY;

    typedef struct _SYSTEM_PROCESS_INFORMATION {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER Reserved[3];         
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        // followed by SYSTEM_THREAD_INFORMATION array which we don't parse
    } SYSTEM_PROCESS_INFORMATION;

    static const ULONG SystemProcessInformation = 5;

    //Get array of SYSTEM_PROCESS_INFORMATION
    while (true) 
    {
        buffer.resize(bufferSize);
        status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &returnLen); // 5 = SystemProcessInformation
        if (status == STATUS_INFO_LENGTH_MISMATCH) 
        {
            if (returnLen > bufferSize) 
                bufferSize = returnLen;
            else 
                bufferSize += 10000;
            continue;
        }
        else if (status < 0) 
        {
            return false;
        }
        break;
    }

    auto make_wstring_from_unicode_string = [](const UNICODE_STRING& u) ->std::wstring
        {
            if (u.Length == 0 || u.Buffer == nullptr) 
                return std::wstring();
            // Length is in bytes
            return std::wstring(u.Buffer, u.Length / sizeof(WCHAR));
        };



    BYTE* ptr = buffer.data();
    const BYTE* bufferEnd = buffer.data() + buffer.size();

    while (ptr < bufferEnd) 
    {
        SYSTEM_PROCESS_INFORMATION* spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(ptr);

        std::wstring name = make_wstring_from_unicode_string(spi->ImageName);
        if (name.empty())
        {
            // System process (often PID 0) or unnamed
            name = L"<System Process>";
        }

        processes.push_back({ spi->UniqueProcessId, spi->InheritedFromUniqueProcessId, name });

        if (spi->NextEntryOffset == 0) 
            break; // last entry
        ptr += spi->NextEntryOffset;
    }

    return true;
}

bool ProcessManager::GetAllSystemModules(std::vector<SystemModuleInfo>& systemModules)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
        return false;
    
    ULONG bufSize = 0x1;
    std::vector<BYTE> buffer(bufSize);
    ULONG needed = 0;

    typedef struct _RTL_PROCESS_MODULE_INFORMATION {
        HANDLE  Section;
        PVOID   MappedBase;
        PVOID   ImageBase;
        ULONG   ImageSize;
        ULONG   Flags;
        USHORT  LoadOrderIndex;
        USHORT  InitOrderIndex;
        USHORT  LoadCount;
        USHORT  OffsetToFileName;
        UCHAR   FullPathName[256];
    } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

    typedef struct _RTL_PROCESS_MODULES {
        ULONG NumberOfModules;
        RTL_PROCESS_MODULE_INFORMATION Modules[1];
    } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

    static const ULONG SystemModuleInformation = 11;
    static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xC0000004L;

    NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer.data(), bufSize, &needed);

    if (status == STATUS_INFO_LENGTH_MISMATCH) 
    {
        buffer.resize(needed);
        status = NtQuerySystemInformation(SystemModuleInformation, buffer.data(), needed, &needed);
    }

    if (status < 0) 
    {
        return false;
    }

    auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer.data());

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) 
    {
        auto& module = modules->Modules[i];

        std::string fullPathstr = reinterpret_cast<char*>(module.FullPathName);
        std::string fileNamestr = reinterpret_cast<char*>(module.FullPathName + module.OffsetToFileName);

        std::wstring fullPathwstr(fullPathstr.begin(), fullPathstr.end());
        size_t pos = fullPathwstr.find(L"\\SystemRoot");
        if (pos != std::string::npos)
            fullPathwstr.replace(pos, wcslen(L"\\SystemRoot"), L"C:\\Windows");

        std::wstring fileNamewstr(fileNamestr.begin(), fileNamestr.end());

        systemModules.push_back(SystemModuleInfo{ fileNamewstr, fullPathwstr });
    }

    return true;
}
