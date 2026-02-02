#include "pch.h"
#include "SystemProcessDefender.h"
#include <memory>

//static member definitions
const std::string SystemProcessDefender::LogModuleName = "System Process Guard"; // System Process Guard

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

void SystemProcessDefender::GetSystem32Processes(std::vector<SystemProcessDefender::SystemProcessInfo>& systemProcesses, std::vector<SystemProcessDefender::SystemProcessInfo>& nonSystemSystem32Processes)
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
            bool gotPath = ProcessManager::GetProcessImagePath(pid, path);

            std::wstring domain, user;
            bool gotOwner = this->processManager.GetProcessOwner(pid, domain, user);

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
                systemProcesses.push_back(SystemProcessDefender::SystemProcessInfo{ pid, gotPath ? path : L"<no path>", domain, user });
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
                        nonSystemSystem32Processes.push_back(SystemProcessDefender::SystemProcessInfo{ pid, path, domain, user });
                    }
                }
            }

        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// Compare executable sections in-memory vs on-disk main module
bool SystemProcessDefender::CompareImageSectionsWithDisk(DWORD pid, std::vector<SectionMismatch>& outMismatches, std::wstring& outMainModulePath)
{
    outMismatches.clear();
    outMainModulePath.clear();

    // get main module base & path
    uintptr_t base = 0;
    if (!ProcessManager::GetMainModuleBase(pid, base, outMainModulePath))
        return false;

    // map file on disk
    HANDLE handleFile = CreateFileW(outMainModulePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handleFile == INVALID_HANDLE_VALUE) 
        return false;
    HANDLE handleFileMapping = CreateFileMappingW(handleFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!handleFileMapping) 
    { 
        CloseHandle(handleFile); 
        return false; 
    }
    LPVOID mapView = MapViewOfFile(handleFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!mapView) 
    { 
        CloseHandle(handleFileMapping); 
        CloseHandle(handleFile); 
        return false; 
    }

    // parse PE headers on disk
    BYTE* fileBase = (BYTE*)mapView;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)fileBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) 
    { 
        UnmapViewOfFile(mapView); 
        CloseHandle(handleFileMapping); 
        CloseHandle(handleFile); 
        return false; 
    }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(fileBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) 
    { 
        UnmapViewOfFile(mapView); 
        CloseHandle(handleFileMapping); 
        CloseHandle(handleFile); 
        return false; 
    }

    WORD numberOfSections = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    // open process for reading
    HANDLE handleProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!handleProcess) 
    { 
        UnmapViewOfFile(mapView); 
        CloseHandle(handleFileMapping); 
        CloseHandle(handleFile); 
        return false; 
    }

    // iterate sections; we compare sections marked executable (or CODE) and non-zero SizeOfRawData
    for (WORD i = 0; i < numberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER& sectionHeader = sections[i];
        DWORD characteristics = sectionHeader.Characteristics;
        bool isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) || (characteristics & IMAGE_SCN_CNT_CODE);
        if (!isExecutable) 
            continue;

        SIZE_T virtualSize = std::max<ULONG>(sectionHeader.Misc.VirtualSize, sectionHeader.SizeOfRawData);
        if (virtualSize == 0) 
            continue;

        uintptr_t remoteAddr = base + sectionHeader.VirtualAddress;
        std::vector<BYTE> remoteBuf(virtualSize);
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(handleProcess, (LPCVOID)remoteAddr, remoteBuf.data(), virtualSize, &bytesRead))
        {
            // cannot read region - record as mismatch (or note we couldn't read)
            SectionMismatch m;
            m.sectionName.resize(IMAGE_SIZEOF_SHORT_NAME);
            MultiByteToWideChar(CP_UTF8, 0, (char*)sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME, m.sectionName.data(), IMAGE_SIZEOF_SHORT_NAME);
            m.offsetInSection = 0;
            m.length = 0;
            outMismatches.push_back(std::move(m));
            continue;
        }

        // get corresponding on-disk bytes
        SIZE_T onDiskSize = sectionHeader.SizeOfRawData;
        if (onDiskSize == 0) onDiskSize = virtualSize;
        BYTE* onDiskPtr = fileBase + sectionHeader.PointerToRawData;

        // compare byte-by-byte; find contiguous mismatches
        SIZE_T pos = 0;
        while (pos < virtualSize)
        {
            if (pos >= onDiskSize) 
            {
                // beyond raw data -> treat as mismatch
                SectionMismatch sectionMismatch;
                sectionMismatch.sectionName.resize(IMAGE_SIZEOF_SHORT_NAME);
                MultiByteToWideChar(CP_UTF8, 0, (char*)sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME, sectionMismatch.sectionName.data(), IMAGE_SIZEOF_SHORT_NAME);
                sectionMismatch.offsetInSection = pos;
                sectionMismatch.length = virtualSize - pos;
                // capture small sample
                SIZE_T sample = std::min<SIZE_T>(64, virtualSize - pos);
                sectionMismatch.expected.assign(onDiskPtr + pos, onDiskPtr + pos + std::min<SIZE_T>(sample, onDiskSize > pos ? sample : 0));
                sectionMismatch.actual.assign(remoteBuf.begin() + pos, remoteBuf.begin() + pos + sample);
                outMismatches.push_back(std::move(sectionMismatch));
                break;
            }

            if (remoteBuf[pos] != onDiskPtr[pos])
            {
                SIZE_T start = pos;
                SIZE_T len = 1;
                ++pos;
                while (pos < virtualSize && pos < onDiskSize && remoteBuf[pos] != onDiskPtr[pos])
                { 
                    ++pos; 
                    ++len; 
                }

                /*
                We skip mismatches that are under 12 bytes.
                Minimal size for a trivial code hook is 12 bytes.
                Hooks can still be achievied with < 12 byte patches but are far harder to implement so we skip.
                */
                if (len < this->MINIMAL_REPORTED_MISMATCH_SIZE) 
                    continue;

                SectionMismatch sectionMismatch;
                sectionMismatch.sectionName.resize(IMAGE_SIZEOF_SHORT_NAME);
                MultiByteToWideChar(CP_UTF8, 0, (char*)sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME, sectionMismatch.sectionName.data(), IMAGE_SIZEOF_SHORT_NAME);
                sectionMismatch.offsetInSection = start;
                sectionMismatch.length = len;
                SIZE_T sample = std::min<SIZE_T>(64, len);
                sectionMismatch.expected.assign(onDiskPtr + start, onDiskPtr + start + std::min<SIZE_T>(sample, onDiskSize - start));
                sectionMismatch.actual.assign(remoteBuf.begin() + start, remoteBuf.begin() + start + sample);
                outMismatches.push_back(std::move(sectionMismatch));
            }
            else 
                ++pos;
        }
    }

    CloseHandle(handleProcess);
    UnmapViewOfFile(mapView);
    CloseHandle(handleFileMapping);
    CloseHandle(handleFile);
    return true;
}

bool SystemProcessDefender::DiskMemoryIntegrityCheckSystemProcesses()
{

    std::vector<SystemProcessDefender::SystemProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::SystemProcessInfo> system32NonSystemUsers;
    this->GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::SystemProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());
    LogsManager logsManager;
    for (auto& process : allSystem32Processes)
    {
        std::vector<SystemProcessDefender::SectionMismatch> sectionMismatches;
        std::wstring mainModulePath;
        this->CompareImageSectionsWithDisk(process.pid, sectionMismatches, mainModulePath);
        for (auto& sectionMismatch : sectionMismatches)
        {
            std::wstringstream extra_info; 
            extra_info << L"Mismatch in section: " << sectionMismatch.sectionName << L"at offset: " << sectionMismatch.offsetInSection << L"\nExpected bytes:";
            for (auto& byte : sectionMismatch.expected)
                extra_info << L" " << std::hex << byte;
            extra_info << L"\nActual bytes:";
            for (auto& byte : sectionMismatch.actual)
                extra_info << L" " << std::hex << byte;
            std::wstring extra_info_wstr = extra_info.str();

            std::wstring processname = process.path.substr(process.path.find_last_of('\\'));

            LogsManager::log_entry logentry;
            logentry.Type = "Memory anomaly";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Filename = std::string(processname.begin(), processname.end());
            logentry.Location = std::string(process.path.begin(), process.path.end());
            logentry.Description = "Code in this process was modified during runtime, this could indicate that it was tampered with.";
            logentry.Extra_info = std::string(extra_info_wstr.begin(), extra_info_wstr.end());

            LogsManager::Log(logentry);
        }
    }

    return true;
}

// Scan memory for list of signatures (vector of pair(hexPattern, name)) hexPattern - ascii hex bytes, spaces allowed, '?' wildcard allowed
/*
Example signature:

std::string sig = "48 8B 0D ? ? ? ? 89 C0 48 8B ? ? 48 ? ? ? ? 48 8B";
std::wstring name = L"exampleSignature";
std::pair<std::string, std::wstring> examplePair(sig, name);
*/
bool SystemProcessDefender::ScanExecutableMemoryForSignatures(DWORD pid, const std::vector<std::pair<std::string, std::wstring>>& signatures, std::vector<SignatureHit>& outHits)
{
    outHits.clear();
    HANDLE handleProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!handleProcess) 
        return false;

    // iterate address space via VirtualQueryEx
    SYSTEM_INFO systemInfo; GetSystemInfo(&systemInfo);
    uintptr_t currentMemoryRegionAddress = (uintptr_t)systemInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION memoryBasicInformation;
    while (currentMemoryRegionAddress < (uintptr_t)systemInfo.lpMaximumApplicationAddress)
    {
        if (VirtualQueryEx(handleProcess, (LPCVOID)currentMemoryRegionAddress, &memoryBasicInformation, sizeof(memoryBasicInformation)) == 0) 
            break;
        if (memoryBasicInformation.State == MEM_COMMIT)
        {
            // choose readable and executable regions
            bool readable_and_executable = false;
            if (memoryBasicInformation.Protect & PAGE_EXECUTE_READ || memoryBasicInformation.Protect & PAGE_EXECUTE_READWRITE)
                readable_and_executable = true;

            if (readable_and_executable)
            {
                SIZE_T regionSize = memoryBasicInformation.RegionSize;
                std::vector<BYTE> buf(regionSize);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(handleProcess, memoryBasicInformation.BaseAddress, buf.data(), regionSize, &bytesRead))
                {
                    // for each signature pattern
                    for (auto& signature : signatures)
                    {
                        std::vector<BYTE> pattern;
                        std::string mask;
                        this->signatureManager.ParseHexPattern(signature.first, pattern, mask);
                        if (pattern.empty()) 
                            continue;
                        // search in buffer
                        uintptr_t foundOffset = this->signatureManager.FindPattern(buf.data(), bytesRead, pattern, mask);
                        if (foundOffset != 0 || (foundOffset == 0 && bytesRead >= pattern.size() && memcmp(buf.data(), pattern.data(), pattern.size()) == 0))
                        {
                            // If pattern found multiple times in region, we only report first
                            uintptr_t absolute = (uintptr_t)memoryBasicInformation.BaseAddress + foundOffset;
                            SignatureHit hit;
                            hit.name = signature.second;
                            hit.address = (PVOID)absolute;
                            outHits.push_back(hit);
                        }
                    }
                }
            }
        }
        currentMemoryRegionAddress = (uintptr_t)memoryBasicInformation.BaseAddress + memoryBasicInformation.RegionSize;
    }

    CloseHandle(handleProcess);
    return true;
}

bool SystemProcessDefender::ScanAllProcessesForBlacklistedSignatures()
{
    std::pair<std::string, std::wstring> exampleSig("48 B8 ? ? ? ? ? ? ? ? FF E0", L"hook_sig1");
    SignatureManager::AddCodeSignatureToDatabase(exampleSig);

    std::vector<ProcessManager::ProcessInfo> processes;
    if (!ProcessManager::GetAllProcesses(processes))
        return false;

    for (auto& process : processes)
    {
        std::wstring filePath; 
        ProcessManager::GetProcessImagePath(reinterpret_cast<DWORD>(process.processID), filePath);
        
        std::vector<SystemProcessDefender::SignatureHit> sigHits;
        if (!this->ScanExecutableMemoryForSignatures(reinterpret_cast<DWORD>(process.processID), SignatureManager::CodeSignatureDatabase, sigHits))
        {
            LogsManager::log_entry logentry;
            logentry.Type = "Error";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Filename = std::string(process.processName.begin(), process.processName.end());
            logentry.Description = "Failed to scan this file for code signature scan";

            LogsManager::Log(logentry);
            continue;
        }
        for (auto& sigHit : sigHits)
        {
            std::ostringstream extra_info_ss;
            extra_info_ss << "Signature " << std::string(sigHit.name.begin(), sigHit.name.end()) << " was found at an address: " << std::hex << sigHit.address;

            LogsManager::log_entry logentry;
            logentry.Type = "Memory anomaly";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Filename = std::string(process.processName.begin(), process.processName.end());
            logentry.Location = std::string(filePath.begin(), filePath.end());
            logentry.Description = "A blacklisted code signature was found in this process";
            logentry.Extra_info = extra_info_ss.str();

            LogsManager::Log(logentry);
        }
    }
}

// Check each thread's current instruction pointer and verify it's inside an executable section of main module.
// Returns threads where instruction pointer is outside original executable sections (suspicious)
bool SystemProcessDefender::CheckThreadsExecution(DWORD pid, std::vector<ThreadSuspicious>& outSuspiciousThreads)
{
    outSuspiciousThreads.clear();

    // first get main module executable sections and address range
    uintptr_t base = 0;
    std::wstring mainPath;
    if (!ProcessManager::GetMainModuleBase(pid, base, mainPath))
        return false;

    // parse module's sections on-disk to gather executable ranges (filemapping technique)
    HANDLE handleFile = CreateFileW(mainPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handleFile == INVALID_HANDLE_VALUE) 
        return false;

    HANDLE handleFileMapping = CreateFileMappingW(handleFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!handleFileMapping) 
    { 
        CloseHandle(handleFile); 
        return false; 
    }

    LPVOID mapView = MapViewOfFile(handleFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!mapView) 
    { 
        CloseHandle(handleFileMapping); 
        CloseHandle(handleFile); 
        return false; 
    }

    // get main module executable memory ranges
    BYTE* fileBase = (BYTE*)mapView;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)fileBase;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(fileBase + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    std::vector<std::pair<uintptr_t, uintptr_t>> executableRanges; // <start, end>
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER& sectionHeader = sections[i];
        if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE || sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE)
        {
            uintptr_t start = base + sectionHeader.VirtualAddress;
            uintptr_t end = start + std::max<ULONG>(sectionHeader.Misc.VirtualSize, sectionHeader.SizeOfRawData);
            executableRanges.emplace_back(start, end);
        }
    }

    UnmapViewOfFile(mapView);
    CloseHandle(handleFileMapping);
    CloseHandle(handleFile);

    // enumerate threads of process
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hsnap == INVALID_HANDLE_VALUE) 
        return false;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (!Thread32First(hsnap, &te))
    {
        CloseHandle(hsnap);
        return false;
    }

    // for each thread belonging to pid, open and suspend to read context
    do
    {
        if (te.th32OwnerProcessID != pid) 
            continue;
        DWORD tid = te.th32ThreadID;
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
        if (!hThread) 
            continue;
        // suspend
        if (SuspendThread(hThread) == (DWORD)-1)
        {
            CloseHandle(hThread);
            continue;
        }


        /*
        Based on the architecture we either work with 32bit or 64bit registers
        alongside fundamental architectural differences
        *THIS PROJECTS IS EXPECTED TO BE COMPATIBLE ONLY WITH X86(64bit&32bit) ARCHITECTURE*
        */
        CONTEXT ctx;
#ifdef _M_X64
        RtlZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx))
        {
            uintptr_t instructionPointer = (uintptr_t)ctx.Rip; //RIP = pointer to next instruction to be executed
            bool inside = false;
            for (auto& executableRange : executableRanges) 
            { 
                if (instructionPointer >= executableRange.first && instructionPointer < executableRange.second) 
                { 
                    inside = true; 
                    break; 
                } 
            }
            if (!inside)
            {
                ThreadSuspicious ts; 
                ts.threadID = tid; 
                ts.instructionPointer = instructionPointer; 
                ts.instructionPointerInsideExecutableSection = false;
                outSuspiciousThreads.push_back(ts);
            }
        }
#else
        RtlZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx))
        {
            uintptr_t ip = (uintptr_t)ctx.Eip; //EIP = pointer to next instruction to be executed
            bool inside = false;
            for (auto& r : execRanges) 
            { 
                if (ip >= r.first && ip < r.second) 
                { 
                    inside = true; 
                    break; 
                } 
            }
            if (!inside)
            {
                ThreadSuspicious ts; 
                ts.tid = tid; 
                ts.ip = ip; 
                ts.ipInsideExecutableSection = false;
                outSuspiciousThreads.push_back(ts);
            }
        }
#endif

        ResumeThread(hThread);
        CloseHandle(hThread);

    } while (Thread32Next(hsnap, &te));
    CloseHandle(hsnap);

    return true;
}

bool SystemProcessDefender::ScanSystemProcessesThreadsSuspiciousExecution()
{        
    std::vector<SystemProcessDefender::SystemProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::SystemProcessInfo> system32NonSystemUsers;
    this->GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::SystemProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());
    for (auto& process : allSystem32Processes)
    {
        std::vector<SystemProcessDefender::ThreadSuspicious> outSuspiciousThreads;
        if (!this->CheckThreadsExecution(process.pid, outSuspiciousThreads))
        {
            std::wstring filenamewstr = process.path.substr(process.path.find_last_of('\\'));
            
            LogsManager::log_entry logentry;
            logentry.Type = "Error";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Filename = std::string(filenamewstr.begin(), filenamewstr.end());
            logentry.Location = std::string(process.path.begin(), process.path.end());
            logentry.Description = "Failed to scan this system process's threads for suspicious execution";

            LogsManager::Log(logentry);
            continue;
        }

        for (auto& suspiciousThread : outSuspiciousThreads)
        {
            std::wstring filenamewstr = process.path.substr(process.path.find_last_of('\\'));

            std::ostringstream extra_info_ss;
            extra_info_ss << "Thread with ID: " << suspiciousThread.threadID << " was found to be executing memory at: " << std::hex << suspiciousThread.instructionPointer << ". This memory address is outside of original executable memory ranges.";

            LogsManager::log_entry logentry;
            logentry.Type = "Memory anomaly";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Filename = std::string(filenamewstr.begin(), filenamewstr.end());
            logentry.Location = std::string(process.path.begin(), process.path.end());
            logentry.Description = "A thread of this process was detected to be executing code outside its original code address space";
            logentry.Extra_info = extra_info_ss.str();

            LogsManager::Log(logentry);
        }
    }
    
    return false;
}

bool SystemProcessDefender::FindSuspiciousExecutableAllocations(DWORD pid, std::vector<SuspiciousAllocation>& outAllocs)
{
    outAllocs.clear();

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc)
    {
        return false;
    }

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    uintptr_t addr = (uintptr_t)systemInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)systemInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION memoryBasicInformation;
    while (addr < maxAddr)
    {
        SIZE_T q = VirtualQueryEx(hProc, (LPCVOID)addr, &memoryBasicInformation, sizeof(memoryBasicInformation));
        if (q == 0)
        {
            // if VirtualQueryEx fails, we increment by page size to avoid infinite loop
            addr += 0x1000;
            continue;
        }

        // only 'commited' memory regions are checked
        if (memoryBasicInformation.State == MEM_COMMIT)
        {
            // MEM_PRIVATE (VirtualAlloc/VirtualAllocEx) or MEM_MAPPED (NtMapViewOfSection)
            if (memoryBasicInformation.Type == MEM_PRIVATE || memoryBasicInformation.Type == MEM_MAPPED)
            {
                if (this->processManager.IsExecuteProtection(memoryBasicInformation.Protect))
                {
                    SuspiciousAllocation s;
                    s.baseAddress = memoryBasicInformation.BaseAddress;
                    s.regionSize = memoryBasicInformation.RegionSize;
                    s.protect = memoryBasicInformation.Protect;
                    s.type = memoryBasicInformation.Type;
                    s.mappedFile.clear();
                    s.writableExecutable = this->processManager.IsWritableExecutable(memoryBasicInformation.Protect);

                    // the memory could also be a mapped file or shared memory.
                    // try to get the potential mapped file's path and convert it to DOS path
                    wchar_t mapped[MAX_PATH] = { 0 };
                    if (GetMappedFileNameW(hProc, memoryBasicInformation.BaseAddress, mapped, _countof(mapped)))
                    {
                        std::wstring device(mapped);
                        std::wstring dos = this->processManager.DevicePathToDosPath(device);
                        s.mappedFile = dos;
                    }


                    outAllocs.push_back(std::move(s));
                }
            }
        }

        // advance to next region
        addr = (uintptr_t)memoryBasicInformation.BaseAddress + memoryBasicInformation.RegionSize;
    }

    CloseHandle(hProc);
    return true;
}

bool SystemProcessDefender::ScanSystemProcessesForSuspiciousMemAllocations(std::vector<std::unique_ptr<LogsManager::log_entry>>& logQueue, std::mutex& lQ_mutex)
{       
    std::vector<SystemProcessDefender::SystemProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::SystemProcessInfo> system32NonSystemUsers;
    this->GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::SystemProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());

    std::unique_lock<std::mutex> lQ_ulock(lQ_mutex, std::defer_lock);
    std::vector<SystemProcessDefender::SuspiciousAllocation> allocations;    
    for (auto& process : allSystem32Processes)
    {
        if (!this->FindSuspiciousExecutableAllocations(process.pid, allocations))
        {
            LogsManager::log_entry logentry;
            logentry.Type = "Error";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Date = LogsManager::GetCurrentDate();
            logentry.Location = std::string(process.path.begin(), process.path.end());
            logentry.Description = "Couldn't scan this process for suspicious allocations of executable memory";

            auto logentryPtr = std::make_unique<LogsManager::log_entry>(logentry);  // Uses default copy constructor of log_entry to initialize with logentry's field values
            lQ_ulock.lock();
                logQueue.push_back(std::move(logentryPtr));      // Should destroy logentryPtr at the end of scope
            lQ_ulock.unlock();            
            continue;
        }

        for (auto& allocation : allocations)
        {
            std::ostringstream extra_info_ss;


            extra_info_ss << "Found suspicious allocation in process " << std::string(process.path.begin(), process.path.end()) << ". At: " << std::hex << allocation.baseAddress
                << " size=" << allocation.regionSize
                << " protection=0x" << std::hex << allocation.protect << std::dec
                << " type=" << (allocation.type == MEM_PRIVATE ? "PRIVATE" : "MAPPED")
                << (allocation.writableExecutable ? " [W+X]" : " [X]") << "\n";
            if (!allocation.mappedFile.empty())
                extra_info_ss << "  mapped file: " << std::string(allocation.mappedFile.begin(), allocation.mappedFile.end()) << "\n";
            
            LogsManager::log_entry logentry;
            logentry.Type = "Memory anomaly";
            logentry.Module_name = SystemProcessDefender::LogModuleName;
            logentry.Date = LogsManager::GetCurrentDate();
            logentry.Location = std::string(process.path.begin(), process.path.end());
            logentry.Description = "A suspicious allocation of executable memory was found in this process.";
            logentry.Extra_info = extra_info_ss.str();

            auto logentryPtr = std::make_unique<LogsManager::log_entry>(logentry);
            lQ_ulock.lock();
                logQueue.push_back(std::move(logentryPtr));
            lQ_ulock.unlock();                        
        }
    }   
    return true;
}
