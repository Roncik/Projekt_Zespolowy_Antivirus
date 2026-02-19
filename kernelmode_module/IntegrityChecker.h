#pragma once
class IntegrityChecker
{
public:
#define MAX_MISMATCH_THRESHOLD 11

#define MAX_PATH_LEN 260
#define MAX_SECTION_LEN 16
#define MAX_PATCH_BYTES 64  // Only capture first 64 bytes of the hook

    typedef struct _Code_Patch
    {
        char FilePath[MAX_PATH_LEN];
        char SectionName[MAX_SECTION_LEN];
        ULONG RVA;
        ULONG Length;
        unsigned char OriginalBytes[MAX_PATCH_BYTES];
        unsigned char ActualBytes[MAX_PATCH_BYTES];
    } Code_Patch, *PCode_Patch;

    // Header to tell User Mode how many items follow
    typedef struct _SCAN_RESULTS_HEADER {
        ULONG Count;
        // PATCH_RESULT_ENTRY Entries[Count]; // Variable length array follows
    } SCAN_RESULTS_HEADER, * PSCAN_RESULTS_HEADER;

    typedef struct _PATCH_NODE {
        LIST_ENTRY ListEntry;
        Code_Patch Data;
    } PATCH_NODE, * PPATCH_NODE;

    // Read file binary into buffer
    static NTSTATUS ReadFileFromDisk(PCHAR FilePath, PVOID* Buffer, SIZE_T* Size);

    // Verify code integrity of the given kernel module
    static NTSTATUS VerifyDriver(AUX_MODULE_EXTENDED_INFO* module);

    inline static FAST_MUTEX ResultMutex;
    inline static LIST_ENTRY ResultListHead;
    inline static ULONG ResultCount = 0;

    // Add an entry to the result list
    static void ReportPatch(const char* path, const char* section, ULONG rva, ULONG len, PUCHAR disk, PUCHAR mem);

    // Clear and deallocate the result list
    static void ClearResults();

    // Verify integrity of all kernel modules
    static void ScanAllKernelModules();
};
