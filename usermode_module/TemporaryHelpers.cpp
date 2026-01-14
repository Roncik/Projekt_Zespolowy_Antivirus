#include "pch.h"
#include "TemporaryHelpers.h"
#include "SystemProcessDefender.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>


//Integrity check System32 processes (file-memory)
void moduleDeployer::runIntegrityCheck(bool* scanRunning, std::mutex &sR_mutex, std::mutex &oL_mutex, std::vector<std::wstring> &outputLines)
{    
    std::unique_lock<std::mutex> sR_lock(sR_mutex);
        *scanRunning = true;
    sR_lock.unlock();

    SystemProcessDefender spd;
    std::vector<SystemProcessDefender::SystemProcessInfo> systemProcesses;
    std::vector<SystemProcessDefender::SystemProcessInfo> system32NonSystemUsers;
    spd.GetSystem32Processes(systemProcesses, system32NonSystemUsers);

    std::vector<SystemProcessDefender::SystemProcessInfo> allSystem32Processes = systemProcesses;
    allSystem32Processes.insert(allSystem32Processes.end(), system32NonSystemUsers.begin(), system32NonSystemUsers.end());
    for (auto& process : allSystem32Processes)
    {
        std::unique_lock<std::mutex> oL_lock(oL_mutex);
            outputLines.push_back(L"Now comparing file-memory of " + process.path + L"\n");
        oL_lock.unlock();
        std::vector<SystemProcessDefender::SectionMismatch> sectionMismatches;
        std::wstring mainModulePath;
        spd.CompareImageSectionsWithDisk(process.pid, sectionMismatches, mainModulePath);
        for (auto& sectionMismatch : sectionMismatches)
        {
            oL_lock.lock();
                outputLines.push_back(L"Mismatch in section: " + sectionMismatch.sectionName + L". Length: " + std::to_wstring(sectionMismatch.length) + L"\n");
                outputLines.push_back(L"Expected bytes:");
                for (auto& originalByte : sectionMismatch.expected)
                    outputLines.push_back(L" " + originalByte);
                outputLines.push_back(L"\n");
                outputLines.push_back(L"Actual bytes:");
                for (auto& changedByte : sectionMismatch.actual)
                    outputLines.push_back(L" " + changedByte);
                outputLines.push_back(L"\n");
            oL_lock.unlock();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }    
    sR_lock.lock();
        *scanRunning = false;
    sR_lock.unlock();
}