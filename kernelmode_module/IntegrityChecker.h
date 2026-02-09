#pragma once

class IntegrityChecker
{
#define MAX_MISMATCH_THRESHOLD 11
    // Read file binary into buffer
    static NTSTATUS ReadFileFromDisk(PCHAR FilePath, PVOID* Buffer, SIZE_T* Size);

    // Verify code integrity of the given kernel module
    static NTSTATUS VerifyDriver(AUX_MODULE_EXTENDED_INFO* module);

public:
    // Verify integrity of all kernel modules
    static void ScanAllKernelModules();
};

