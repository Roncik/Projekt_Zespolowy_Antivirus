#pragma once
#include "ProcessManager.h"
#include "SignatureManager.h"

class SystemProcessDefender
{
private:
    ProcessManager processManager;
    SignatureManager signatureManager;

public:
    struct SystemProcessInfo
    {
        DWORD pid;
        std::wstring path;
        std::wstring domain;
        std::wstring user;
    };

    struct SectionMismatch 
    {
        std::wstring sectionName;
        SIZE_T offsetInSection;
        SIZE_T length;
        // dump of the first 64 mismatching bytes
        std::vector<BYTE> expected;
        std::vector<BYTE> actual;
    };

    struct SignatureHit 
    {
        std::wstring name;
        PVOID address;
    };

    struct ThreadSuspicious 
    {
        DWORD threadID;
        uintptr_t instructionPointer;
        bool instructionPointerInsideExecutableSection;
    };

    struct SuspiciousAllocation
    {
        LPVOID baseAddress;
        SIZE_T regionSize;
        DWORD protect;   
        DWORD type;      // MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE
        std::wstring mappedFile; // possible mapped file (if any), empty if unknown
        bool writableExecutable; // true if RW + EXEC
    };


    static const SIZE_T MINIMAL_REPORTED_MISMATCH_SIZE = 12;


    bool VerifyEmbeddedSignature(const std::wstring& filePath);

    void GetSystem32Processes(std::vector<SystemProcessInfo>& systemProcesses, std::vector<SystemProcessInfo>& nonSystemSystem32Processes);

    bool CompareImageSectionsWithDisk(DWORD pid, std::vector<SectionMismatch>& outMismatches, std::wstring& outMainModulePath);

    bool ScanExecutableMemoryForSignatures(DWORD pid, const std::vector<std::pair<std::string, std::wstring>>& signatures, std::vector<SignatureHit>& outHits);

    bool CheckThreadsExecution(DWORD pid, std::vector<ThreadSuspicious>& outSuspiciousThreads);

    bool FindSuspiciousExecutableAllocations(DWORD pid, std::vector<SuspiciousAllocation>& outAllocs);
};

