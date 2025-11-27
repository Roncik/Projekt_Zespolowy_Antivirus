#include "pch.h"
#include "SystemProcessDefender.h"


int wmain()
{
    //SystemProcessDefender spd;
    //
    //std::vector<SystemProcessDefender::ProcessInfo> systemProcesses; 
    //std::vector<SystemProcessDefender::ProcessInfo> system32NonSystemUsers; 

    //spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);


    //// Output results
    //std::wcout << L"--- Found system processes (user = NT AUTHORITY || SYSTEM) ---\n";
    //if (systemProcesses.empty())
    //{
    //    std::wcout << L"No system processes found (insufficient privilege?).\n";
    //}
    //else
    //{
    //    for (SystemProcessDefender::ProcessInfo t : systemProcesses)
    //    {
    //        std::wcout << L"PID: " << t.pid << L"  Path: " << t.path << L"  User: " << t.domain << L"\\" << t.user << L"\n";

    //        // Verify digital signature
    //        if (t.path != L"<no path>")
    //        {
    //            bool signedOk = spd.VerifyEmbeddedSignature(t.path);
    //            if (signedOk)
    //                std::wcout << L"  -> Digital signature: OK\n";
    //            else
    //                std::wcout << L"  -> Digital signature: Invalid / No Signature\n";
    //        }
    //        else
    //        {
    //            std::wcout << L"  -> Cannot verify signature (no path).\n";
    //        }
    //    }
    //}

    //std::wcout << L"\n--- Processes launched from C:\\Windows\\System32, but NOT by NT AUTHORITY\\SYSTEM ---\n";
    //if (system32NonSystemUsers.empty())
    //{
    //    std::wcout << L"No processes from System32 launched by different accounts.\n";
    //}
    //else
    //{
    //    for (SystemProcessDefender::ProcessInfo t : system32NonSystemUsers)
    //    {
    //        std::wcout << L"PID: " << t.pid << L"  Path: " << t.path << L"  User: " << (t.domain.empty() ? L"<unknown>" : t.domain) << L"\\" << (t.user.empty() ? L"<unknown>" : t.user) << L"\n";
    //    }
    //}

    //std::wcout << L"\nFinished.\n";


    //#1. Integrity check System32 processes (file-memory)

    //Get processes
    SystemProcessDefender spd;
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
    }


    return 0;
}



