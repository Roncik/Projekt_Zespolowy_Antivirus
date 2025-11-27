#pragma once
#include "ProcessManager.h"
#include "SignatureManager.h"

class SystemProcessDefender
{
private:
    ProcessManager processManager;
    SignatureManager signatureManager;

public:
    struct ProcessInfo
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


    static const SIZE_T MINIMAL_REPORTED_MISMATCH_SIZE = 12;


    bool VerifyEmbeddedSignature(const std::wstring& filePath);

    void GetSystem32Processes(std::vector<ProcessInfo>& systemProcesses, std::vector<ProcessInfo>& nonSystemSystem32Processes);

    bool CompareImageSectionsWithDisk(DWORD pid, std::vector<SectionMismatch>& outMismatches, std::wstring& outMainModulePath);

    bool ScanExecutableMemoryForSignatures(DWORD pid, const std::vector<std::pair<std::string, std::wstring>>& signatures, std::vector<SignatureHit>& outHits);

    bool CheckThreadsExecution(DWORD pid, std::vector<ThreadSuspicious>& outSuspiciousThreads);
};

