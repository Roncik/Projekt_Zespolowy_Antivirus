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
