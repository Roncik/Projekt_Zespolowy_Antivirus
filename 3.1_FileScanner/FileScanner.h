#pragma once
#include "MD5_HashManager.h"

class FileScanner
{
private:
    MD5_HashManager MD5HashMgr;
    std::vector<MD5_HashManager::Hash16> MD5HashBlacklist;

public:
	//Scan files in the specified directory against a MD5 blacklist
    void ScanDirectory_MD5(HCRYPTPROV hProv, const std::wstring& startDir, const std::vector<MD5_HashManager::Hash16>& blacklist);
    
    //Scan all directories - all subdirectories of drives A to Z
    void ScanAllDirectories_MD5();
    
    //Load hash blacklist into memory from specified path
    bool LoadBlacklist_MD5(const std::string& path);
};

