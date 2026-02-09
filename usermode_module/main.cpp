#include "pch.h"
#include "MD5_HashManager.h"
#include "FileScanner.h"
#include "SystemProcessDefender.h"
#include "HTTPSManager.h"
#include "VirusTotalManager.h"
#include "ProcessManager.h"
#include "ImGUIManager.h"
#include "ServiceControlManager.h"
#include "ExceptionFilters.h"
//#include "LogsManager.h"

int main()
{
    SetUnhandledExceptionFilter(ExceptionFilters::SimplestCrashHandler);

    
    //Scan all files in the system for blacklisted hash
    {
        /*FileScanner fileScanner;
        fileScanner.LoadBlacklist_MD5(".\\MD5Hashes\\merged_hashes.txt");
        fileScanner.ScanAllDirectories_MD5();*/
    }

    //Integrity check System32 processes (file-memory)
    {
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
                std::wcout << L"Expected bytes:";
                for (auto& originalByte : sectionMismatch.expected)
                    std::wcout << L" " << originalByte;
                std::wcout << L"\n";
                std::wcout << L"Actual bytes:";
                for (auto& changedByte : sectionMismatch.actual)
                    std::wcout << L" " << changedByte;
                std::wcout << L"\n";
            }
        }*/
    }

    //Scan System32 processes for code signatures
    {
       /* SystemProcessDefender spd;
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
    }

    //Scan System32 processes for execution outside of original executable memory ranges    // not this!
    {
        /*SystemProcessDefender spd;

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
        }*/
    }

    //Scan System32 processes for manually allocated memory that is executable.     //not this!
    {
        //After testing, this functionality turns out to not be reliable enough for verifying system process integrity
        //and will be replaced for driver-based hook and monitoring of remote allocations (NtAllocateVirtualMemory/NtMapViewOfSection)
        /*SystemProcessDefender spd;

        std::vector<SystemProcessDefender::ProcessInfo> systemProcesses;
        std::vector<SystemProcessDefender::ProcessInfo> system32NonSystemUsers;
        spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);

        std::vector<SystemProcessDefender::ProcessInfo> allSystem32Processes = systemProcesses;
        allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());

        std::vector<SystemProcessDefender::SuspiciousAllocation> allocations;
        for (auto& process : allSystem32Processes)
        {

            if (spd.FindSuspiciousExecutableAllocations(process.pid, allocations))
            {
                for (auto& allocation : allocations)
                {
                    std::wcout << L"Found suspicious allocation in process " << process.path << L". At: " << allocation.baseAddress
                        << L" size=" << allocation.regionSize
                        << L" protection=0x" << std::hex << allocation.protect << std::dec
                        << L" type=" << (allocation.type == MEM_PRIVATE ? L"PRIVATE" : L"MAPPED")
                        << (allocation.writableExecutable ? L" [W+X]" : L" [X]") << L"\n";
                    if (!allocation.mappedFile.empty())
                        std::wcout << L"  mapped file: " << allocation.mappedFile << L"\n";
                }
            }
            else
            {
                std::wcout << L"Couldn't open process or scan memory (insufficient privileges?).\n";
            }
        }*/
    }

    //VirusTotal analyse file and get result        // not this!
    {
        //VirusTotalManager vtmgr = VirusTotalManager(L"c164bc01db151497cc74f370c2b8d4f41d020d79030db9b9db7eca737869e99e"); //VirusTotal API key https://www.virustotal.com/gui/my-apikey
        //VirusTotalManager::FileAnalysisResult result;

    ////below function will have a long execution time (>60sec) we will use multithreading for the vt scans
    //if (!vtmgr.AnalyseFileGetResult("C:\\Users\\Administrator\\Desktop\\Firefox.exe", result))
    //    std::wcout << L"file analysis failed\n";

    //if (result == VirusTotalManager::FileAnalysisResult::MALICIOUS)
    //    std::wcout << L"file is malicious\n";
    //else if (result == VirusTotalManager::FileAnalysisResult::SUSPICIOUS)
    //    std::wcout << L"file is suspicious\n";
    //else
        //std::wcout << L"file analysis didn't detect anything malicious or suspicious\n";
    }

    //Virustotal scan all running processes's file's and loaded system modules
    {
        //VirusTotalManager vtmgr = VirusTotalManager(L"c164bc01db151497cc74f370c2b8d4f41d020d79030db9b9db7eca737869e99e", L"hashdb.txt"); //VirusTotal API key https://www.virustotal.com/gui/my-apikey 
        //vtmgr.ScanRunningProcessesAndDrivers();
    }
    
    //Run Imgui window
    {
        ImGUIManager imguimgr;
        imguimgr.RunUI();
    }

    //Logger test
    {
        /*LogsManager logsmgr;
        logsmgr.ReadLogsFromFile();
        logsmgr.Log("Antivirus", "Test");*/
    }

    // Another logger test
    //{
    //    SystemProcessDefender spd;
    //    spd.DiskMemoryIntegrityCheckSystemProcesses();
    //    //spd.CheckThreadsExecution();
    //    //spd.FindSuspiciousExecutableAllocations();
    //    spd.ScanSystemProcessesForSuspiciousMemAllocations();
    //}

    // Load Driver, send IOCTL, unload driver
    /*{
        if (!ServiceControlManager::CreateAndStartDriver())
        {
            std::wcout << L"Creating and starting driver failed!" << std::endl; 
            system("pause");
        }
        if (!ServiceControlManager::ExampleIOCTLCall())
        {
            std::wcout << L"IOCTL request failed!" << std::endl;
            system("pause");
        }
        if (!ServiceControlManager::StopDriverAndDeleteService())
        {
            std::wcout << L"unloading driver failed!" << std::endl;
            system("pause");
        }
        system("pause");
    }*/
    return 0;
}
