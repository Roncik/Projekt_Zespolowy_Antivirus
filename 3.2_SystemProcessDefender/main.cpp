#include "pch.h"
#include "SystemProcessDefender.h"


int wmain()
{
    SystemProcessDefender spd;
    
    std::vector<SystemProcessDefender::ProcessInfo> systemProcesses; // pid, path, domain, user
    std::vector<SystemProcessDefender::ProcessInfo> system32NonSystemUsers; // pid, path, domain, user

    spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);


    // Output results
    std::wcout << L"--- Found system processes (user = NT AUTHORITY || SYSTEM) ---\n";
    if (systemProcesses.empty())
    {
        std::wcout << L"No system processes found (insufficient privilege?).\n";
    }
    else
    {
        for (SystemProcessDefender::ProcessInfo t : systemProcesses)
        {
            std::wcout << L"PID: " << t.pid << L"  Path: " << t.path << L"  User: " << t.domain << L"\\" << t.user << L"\n";

            // Verify digital signature
            if (t.path != L"<no path>")
            {
                bool signedOk = spd.VerifyEmbeddedSignature(t.path);
                if (signedOk)
                    std::wcout << L"  -> Digital signature: OK\n";
                else
                    std::wcout << L"  -> Digital signature: Invalid / No Signature\n";
            }
            else
            {
                std::wcout << L"  -> Cannot verify signature (no path).\n";
            }
        }
    }

    std::wcout << L"\n--- Processes launched from C:\\Windows\\System32, but NOT by NT AUTHORITY\\SYSTEM ---\n";
    if (system32NonSystemUsers.empty())
    {
        std::wcout << L"No processes from System32 launched by different accounts.\n";
    }
    else
    {
        for (SystemProcessDefender::ProcessInfo t : system32NonSystemUsers)
        {
            std::wcout << L"PID: " << t.pid << L"  Path: " << t.path << L"  User: " << (t.domain.empty() ? L"<unknown>" : t.domain) << L"\\" << (t.user.empty() ? L"<unknown>" : t.user) << L"\n";
        }
    }

    std::wcout << L"\nFinished.\n";
    return 0;
}



