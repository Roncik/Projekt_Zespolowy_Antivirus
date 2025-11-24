#include "pch.h"
#include "SystemProcessDefender.h"

bool SystemProcessDefender::VerifyEmbeddedSignature(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_IGNORE;
    winTrustData.hWVTStateData = NULL;
    winTrustData.pwszURLReference = NULL;
    winTrustData.dwUIContext = 0;
    winTrustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(NULL, &action, &winTrustData);
    return (status == ERROR_SUCCESS);
}

bool SystemProcessDefender::GetProcessImagePath(DWORD pid, std::wstring& outPath)
{
    outPath.clear();
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    DWORD capacity = 32768; // ample buffer
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

bool SystemProcessDefender::GetProcessOwner(DWORD pid, std::wstring& outDomain, std::wstring& outUser)
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

void SystemProcessDefender::GetSystem32Processes(std::vector<SystemProcessDefender::ProcessInfo>& systemProcesses, std::vector<SystemProcessDefender::ProcessInfo>& nonSystemSystem32Processes)
{
    // prepare windows system32 path for comparisons
    wchar_t winDir[MAX_PATH];
    if (!GetWindowsDirectoryW(winDir, MAX_PATH))
    {
        std::wcout << L"Couldn't get windows directory path\n";
        return;
    }
    std::wstring system32Prefix = winDir;
    if (system32Prefix.back() != L'\\')
        system32Prefix += L'\\';
    system32Prefix += L"System32\\";
    // normalize to lower for case-insensitive compare
    std::transform(system32Prefix.begin(), system32Prefix.end(), system32Prefix.begin(), ::towlower);

    // enumerate all processes via CreateToolhelp32Snapshot
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"CreateToolhelp32Snapshot failed.\n";
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe))
    {
        do
        {
            DWORD pid = pe.th32ProcessID;
            if (pid == 0)
                continue; // skip idle

            std::wstring path;
            bool gotPath = GetProcessImagePath(pid, path);

            std::wstring domain, user;
            bool gotOwner = GetProcessOwner(pid, domain, user);

            // normalize domain and user to upper/lower for comparisons
            std::wstring domainUpper = domain;
            std::wstring userUpper = user;
            std::transform(domainUpper.begin(), domainUpper.end(), domainUpper.begin(), ::towlower);
            std::transform(userUpper.begin(), userUpper.end(), userUpper.begin(), ::towlower);

            bool isSystemAccount = false;
            if (gotOwner)
            {
                // check if domain == "nt authority" or user == "system"
                if (domainUpper.find(L"nt authority") != std::wstring::npos || userUpper == L"system")
                {
                    isSystemAccount = true;
                }
            }

            // If it's a system account, record it
            if (isSystemAccount)
            {
                systemProcesses.push_back(SystemProcessDefender::ProcessInfo{ pid, gotPath ? path : L"<no path>", domain, user });
            }

            // Check if the path is under C:\Windows\System32 but user is NOT NT AUTHORITY/SYSTEM
            if (gotPath)
            {
                std::wstring pathLower = path;
                std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
                if (pathLower.rfind(system32Prefix, 0) == 0) // starts with system32 prefix
                {
                    if (!isSystemAccount)
                    {
                        nonSystemSystem32Processes.push_back(SystemProcessDefender::ProcessInfo{ pid, path, domain, user });
                    }
                }
            }

        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}
