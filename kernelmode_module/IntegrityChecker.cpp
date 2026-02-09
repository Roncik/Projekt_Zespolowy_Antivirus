#include "pch.h"
#include "IntegrityChecker.h"
#include "ForwardDeclarations.h"
#include "Helpers.h"

NTSTATUS IntegrityChecker::ReadFileFromDisk(PCHAR inputPath, PVOID* Buffer, SIZE_T* Size) 
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE handle;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING uPath;
    char attemptPath[260];

    // Simple retry logic for path finding
    BOOLEAN isBare = (strchr(inputPath, '\\') == NULL);
    int attempts = isBare ? 2 : 1;

    for (int i = 0; i < attempts; i++) 
    {
        if (isBare) 
        {
            if (i == 0) 
                RtlStringCbPrintfA(attemptPath, 260, "\\SystemRoot\\System32\\drivers\\%s", inputPath);
            else 
                RtlStringCbPrintfA(attemptPath, 260, "\\SystemRoot\\System32\\%s", inputPath);
        }
        else 
        {
            // Basic prefix normalization
            if (inputPath[1] == ':' && inputPath[2] == '\\') 
                RtlStringCbPrintfA(attemptPath, 260, "\\??\\%s", inputPath);
            else if 
                (_strnicmp(inputPath, "\\Windows\\", 9) == 0) RtlStringCbPrintfA(attemptPath, 260, "\\SystemRoot%s", inputPath + 8);
            else 
                RtlStringCbPrintfA(attemptPath, 260, "%s", inputPath);
        }

        ANSI_STRING as; 
        RtlInitAnsiString(&as, attemptPath);
        if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uPath, &as, TRUE))) 
            break;

        InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenFile(&handle, FILE_GENERIC_READ, &objAttr, &ioStatus, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

        if (NT_SUCCESS(status)) 
        {
            FILE_STANDARD_INFORMATION fi;
            ZwQueryInformationFile(handle, &ioStatus, &fi, sizeof(fi), FileStandardInformation);
            *Size = fi.EndOfFile.LowPart;
            *Buffer = ExAllocatePoolWithTag(NonPagedPool, *Size, DRIVER_TAG);
            if (*Buffer) ZwReadFile(handle, NULL, NULL, NULL, &ioStatus, *Buffer, (ULONG)*Size, NULL, NULL);
            ZwClose(handle);
            RtlFreeUnicodeString(&uPath);
            return *Buffer ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlFreeUnicodeString(&uPath);
    }
    return status;
}


NTSTATUS IntegrityChecker::VerifyDriver(AUX_MODULE_EXTENDED_INFO* module) 
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID fileBuffer = NULL;
    SIZE_T fileSize = 0;

    status = ReadFileFromDisk((PCHAR)module->FullPathName + module->FileNameOffset, &fileBuffer, &fileSize);
    if (!NT_SUCCESS(status) || !fileBuffer) 
        return STATUS_NOT_FOUND;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
    { 
        ExFreePool(fileBuffer); 
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)fileBuffer + dosHeader->e_lfanew);

    ULONG64 actualBase = (ULONG64)module->BasicInfo.ImageBase;

    // Iterate Sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (ULONG i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
    {
        UCHAR lowercaseSectionName[8];
        memcpy(lowercaseSectionName, section->Name, 8);
        Helpers::ToLowerCase(lowercaseSectionName, 8);
        BOOLEAN is_Pagewx_section = memcmp(lowercaseSectionName, "pagewx", 6) == 0;
        // Only Executable Code (skip .rdata/.data etc.) + exclude PAGEwx pages(pages of microsoft's Warbird system)
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) && !is_Pagewx_section)
        {
            PUCHAR diskContent = (PUCHAR)fileBuffer + section->PointerToRawData;
            PUCHAR memContent = (PUCHAR)actualBase + section->VirtualAddress;

            // Safe bounds
            ULONG checkSize = section->SizeOfRawData;
            if (checkSize > section->Misc.VirtualSize) 
                checkSize = section->Misc.VirtualSize;
            if (section->PointerToRawData + checkSize > fileSize) 
                checkSize = (ULONG)(fileSize - section->PointerToRawData);

            ULONG consecutiveMismatches = 0;
            ULONG currentChainStart = 0;

            // Byte by byte comparison
            for (ULONG j = 0; j < checkSize; j++) 
            {
                UCHAR memByte = 0;
                BOOLEAN safe = FALSE;

                // 1. Safe Read from RAM
                __try {
                    memByte = memContent[j];
                    safe = TRUE;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) 
                { 
                    safe = FALSE; 
                }

                if (!safe) 
                {
                    // Reset counter on read error
                    if (consecutiveMismatches > MAX_MISMATCH_THRESHOLD) 
                    {
                        Helpers::Log("[!] DETECTED: %s (Section: %.8s) | Offset: 0x%X | Length: %u bytes\n",
                            module->FullPathName + module->FileNameOffset, section->Name, currentChainStart, consecutiveMismatches);

                        ReportPatch(
                            (char*)(module->FullPathName + module->FileNameOffset),
                            (char*)section->Name,
                            section->VirtualAddress + currentChainStart,
                            consecutiveMismatches,
                            &diskContent[currentChainStart],
                            &memContent[currentChainStart]
                        );
                    }
                    consecutiveMismatches = 0;
                    continue;
                }

                // 2. Compare
                if (diskContent[j] != memByte) 
                {
                    if (consecutiveMismatches == 0) currentChainStart = j;
                    consecutiveMismatches++;
                }
                else 
                {
                    // 3. End of a mismatch chain - if the mismatch is bigger than threshold report it
                    if (consecutiveMismatches > MAX_MISMATCH_THRESHOLD) 
                    {

                        // Heuristic: Check if it looks like a Relocation Block (Consecutive 8 bytes?)
                        // Since we disabled fixups, a pure address (8 bytes) is < 11. 
                        // But two adjacent addresses (16 bytes) would trigger this.

                        Helpers::Log("[!] DETECTED: %s (Section: %.8s) | RVA: 0x%X | Length: %u bytes\n",
                            module->FullPathName + module->FileNameOffset,
                            section->Name,
                            section->VirtualAddress + currentChainStart,
                            consecutiveMismatches);

                        ReportPatch(
                            (char*)(module->FullPathName + module->FileNameOffset),
                            (char*)section->Name,
                            section->VirtualAddress + currentChainStart,
                            consecutiveMismatches,
                            &diskContent[currentChainStart],
                            &memContent[currentChainStart]
                        );

                        // Optional: Print the bytes to DebugView
                    }

                    // Reset counter
                    consecutiveMismatches = 0;
                }
            }

            // Check if section ended with a mismatch chain
            if (consecutiveMismatches > MAX_MISMATCH_THRESHOLD) 
            {
                Helpers::Log("[!] DETECTED: %s (Section: %.8s) | RVA: 0x%X | Length: %u bytes\n",
                    module->FullPathName + module->FileNameOffset, section->Name, section->VirtualAddress + currentChainStart, consecutiveMismatches);
            }
        }
    }

    ExFreePool(fileBuffer);
    return STATUS_SUCCESS;
}

void IntegrityChecker::ReportPatch(const char* path, const char* section, ULONG rva, ULONG len, PUCHAR disk, PUCHAR mem)
{
    PPATCH_NODE node = (PPATCH_NODE)ExAllocatePoolWithTag(NonPagedPool, sizeof(PATCH_NODE), DRIVER_TAG);
    if (!node)
        return;

    RtlZeroMemory(node, sizeof(PATCH_NODE));

    // Fill Flat Data
    RtlStringCbCopyA(node->Data.FilePath, MAX_PATH_LEN, path);
    RtlStringCbCopyA(node->Data.SectionName, MAX_SECTION_LEN, section);
    node->Data.RVA = rva;
    node->Data.Length = len;

    // Cap the bytes we capture to avoid overflowing the struct
    ULONG captureLen = (len > MAX_PATCH_BYTES) ? MAX_PATCH_BYTES : len;

    // Safety check for pointers
    __try {
        if (disk) RtlCopyMemory(node->Data.OriginalBytes, disk, captureLen);
        if (mem)  RtlCopyMemory(node->Data.ActualBytes, mem, captureLen);
    }
    __except (1) {
        // Access violation reading bytes, ignore
    }

    // Lock and Add to List
    ExAcquireFastMutex(&ResultMutex);
    InsertTailList(&ResultListHead, &node->ListEntry);
    ResultCount++;
    ExReleaseFastMutex(&ResultMutex);
}

void IntegrityChecker::ClearResults()
{
    ExAcquireFastMutex(&ResultMutex);
    while (!IsListEmpty(&ResultListHead)) 
    {
        PLIST_ENTRY entry = RemoveHeadList(&ResultListHead);
        PPATCH_NODE node = CONTAINING_RECORD(entry, PATCH_NODE, ListEntry);
        ExFreePoolWithTag(node, DRIVER_TAG);
    }
    ResultCount = 0;
    ExReleaseFastMutex(&ResultMutex);
}


void IntegrityChecker::ScanAllKernelModules() 
{
    // Use AuxKLib to enumerate all loaded kernel modules
    ULONG modulesSize = 0;
    AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (modulesSize == 0) 
        return;

    PAUX_MODULE_EXTENDED_INFO modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(PagedPool, modulesSize, DRIVER_TAG);
    if (!modules) 
        return;

    RtlZeroMemory(modules, modulesSize);
    AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);

    ULONG count = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
    Helpers::Log("[*] Scanning %u modules (Threshold: >%d consecutive bytes)...\n", count, MAX_MISMATCH_THRESHOLD);

    for (ULONG i = 0; i < count; i++) 
    {
        // Kernel address space starts at 0xFFFF000000000000(if base is smaller it is not a typical kernel module)
        if (reinterpret_cast<ULONG64>(modules[i].BasicInfo.ImageBase) > 0xFFFF000000000000) 
        {
            VerifyDriver(&modules[i]);
        }
    }
    Helpers::Log("[*] Scan Complete.\n");
    ExFreePoolWithTag(modules, DRIVER_TAG);
}
