#pragma once
#include "MD5_HashManager.h"
#include "LogsManager.h"

class FileScanner
{
private:
    MD5_HashManager MD5HashMgr;
    std::vector<MD5_HashManager::Hash16> MD5HashBlacklist;
    std::mutex coutMutex;
    std::vector<std::thread> threads;
    inline static const std::string LogModuleName = "VirusTotal";

public:
    //Scan files in the specified directory and all its subdirectories against a MD5 blacklist
    void ScanDirectoryAndAllSubdirectories_MD5(HCRYPTPROV hProv, const std::wstring& startDir, const std::vector<MD5_HashManager::Hash16>& blacklist, std::vector<std::unique_ptr<LogsManager::log_entry>>& logQueue, std::mutex& lQ_mutex);
    
    //Scan all directories - all subdirectories of drives A to Z
    void ScanAllDirectories_MD5(std::vector<std::unique_ptr<LogsManager::log_entry>>& logQueue, std::mutex& lQ_mutex);  // Added proper logging mechanism's integration with GUI
    
    //Load hash blacklist into memory from specified path
    bool LoadBlacklist_MD5(const std::string& path);
};

