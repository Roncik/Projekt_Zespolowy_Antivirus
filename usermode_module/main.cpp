#include "pch.h"
#include "MD5_HashManager.h"
#include "FileScanner.h"
#include "SystemProcessDefender.h"

int main()
{
    //Scan all files in the system for blacklisted hash
    /*FileScanner fileScanner;
    fileScanner.LoadBlacklist_MD5(".\\MD5Hashes\\merged_hashes.txt");
    fileScanner.ScanAllDirectories_MD5();*/

    //Integrity check System32 processes (file-memory)
    /*SystemProcessDefender spd;
    std::vector<SystemProcessDefender::ProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::ProcessInfo> system32NonSystemUsers;
    spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::ProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());
    for (auto& process : allSystem32Processes)
    {
        std::wcout << L"Now comparing file-memory of " << process.path << L"\n";
        std::vector<SystemProcessDefender::SectionMismatch> sectionMismatches;
        std::wstring mainModulePath;
        spd.CompareImageSectionsWithDisk(process.pid, sectionMismatches, mainModulePath);
        for (auto& sectionMismatch : sectionMismatches)
        {
            std::wcout << L"Mismatch in section: " << sectionMismatch.sectionName << L". Length: " << sectionMismatch.length << L"\n";
        }
    }*/

    //Scan System32 processes for code signatures
    /*SystemProcessDefender spd;
    std::pair<std::string, std::wstring> exampleSig("48 B8 ? ? ? ? ? ? ? ? FF E0", L"hook_sig1");
    std::vector<std::pair<std::string, std::wstring>> exampleSigsVector;
    exampleSigsVector.push_back(exampleSig);

    std::vector<SystemProcessDefender::ProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::ProcessInfo> system32NonSystemUsers;
    spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::ProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());
    for (auto& process : allSystem32Processes)
    {
        std::wcout << L"Now scanning " << process.path << L"\n";
        std::vector<SystemProcessDefender::SignatureHit> sigHits;
        spd.ScanExecutableMemoryForSignatures(process.pid, exampleSigsVector, sigHits);
        for (auto& sigHit : sigHits)
        {
            std::wcout << L"Signature found: " << sigHit.name << L". At: " << sigHit.address << L"\n";
        }
    }*/

    //Scan System32 processes for execution outside of original executable memory ranges
    SystemProcessDefender spd;

    std::vector<SystemProcessDefender::ProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::ProcessInfo> system32NonSystemUsers;
    spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::ProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());
    for (auto& process : allSystem32Processes)
    {
        std::wcout << L"Now scanning " << process.path << L"\n";
        std::vector<SystemProcessDefender::ThreadSuspicious> outSuspiciousThreads;
        spd.CheckThreadsExecution(process.pid, outSuspiciousThreads);

        for (auto& suspiciousThread : outSuspiciousThreads)
        {
            std::wcout << L"Suspicious thread found in thread: " << suspiciousThread.threadID << L". IP: " << suspiciousThread.instructionPointer << L"\n";
        }
    }



    return 0;
}
