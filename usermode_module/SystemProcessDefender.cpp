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
            bool gotPath = this->processManager.GetProcessImagePath(pid, path);

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
    if (!this->processManager.GetMainModuleBase(pid, base, outMainModulePath))
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

// Check each thread's current instruction pointer and verify it's inside an executable section of main module.
// Returns threads where instruction pointer is outside original executable sections (suspicious)
bool SystemProcessDefender::CheckThreadsExecution(DWORD pid, std::vector<ThreadSuspicious>& outSuspiciousThreads)
{
    outSuspiciousThreads.clear();

    // first get main module executable sections and address range
    uintptr_t base = 0;
    std::wstring mainPath;
    if (!this->processManager.GetMainModuleBase(pid, base, mainPath)) 
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
