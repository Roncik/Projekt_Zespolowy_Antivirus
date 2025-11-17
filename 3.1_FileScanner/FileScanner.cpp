#include "pch.h"
#include "FileScanner.h"

void FileScanner::ScanDirectory_MD5(HCRYPTPROV hProv, const std::wstring& startDir, const std::vector<MD5_HashManager::Hash16>& blacklist)
{
    if (blacklist.empty())
    {
        std::cerr << "MD5 blacklist is empty. Scan aborted" << std::endl;
        return;
    }
    
    std::vector<std::wstring> stack;
    stack.push_back(startDir);

    while (!stack.empty())
    {
        std::wstring dirPath = std::move(stack.back());
        stack.pop_back();

        // build search pattern "dirPath\*"
        std::wstring searchPath = dirPath;
        if (!searchPath.empty() && searchPath.back() != L'\\')
            searchPath.push_back(L'\\');
        searchPath += L"*";

        WIN32_FIND_DATAW ffd;
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            // can't open this directory (permission, removed, etc.) — skip it
            continue;
        }

        do
        {
            const std::wstring name = ffd.cFileName;
            if (name == L"." || name == L"..") continue;

            std::wstring fullPath = dirPath;
            if (!fullPath.empty() && fullPath.back() != L'\\') fullPath.push_back(L'\\');
            fullPath += name;

            // skip reparse points (junctions/symlinks) to avoid loops
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            {
                continue;
            }

            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                // push subdirectory onto stack for later processing
                stack.push_back(fullPath);
            }
            else
            {
                // compute MD5 and check blacklist
                MD5_HashManager::Hash16 MD5Hash;
                if (MD5HashMgr.computeFileMd5(hProv, fullPath, MD5Hash)) 
                {
                    if (MD5HashMgr.contains_hash(blacklist, MD5Hash))
                    {
                        // convert wide path to UTF-8 for printing
                        int bufSize = WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
                        std::string pathUtf8(bufSize, '\0');
                        WideCharToMultiByte(CP_UTF8, 0, fullPath.c_str(), -1, &pathUtf8[0], bufSize, nullptr, nullptr);
                        if (!pathUtf8.empty() && pathUtf8.back() == '\0') pathUtf8.pop_back();

                        std::cout << "[BLACKLIST MATCH] " << "  ->  " << pathUtf8 << std::endl;
                    }
                }
                else
                {
                    // couldn't open/hash file (locked/permission) — optionally log or ignore
                }
            }

        } while (FindNextFileW(hFind, &ffd) != 0);

        FindClose(hFind);
    }
}

void FileScanner::ScanAllDirectories_MD5()
{
    if (MD5HashBlacklist.empty())
    {
        std::cerr << "MD5 blacklist is empty. Scan aborted" << std::endl;
        return;
    }
    
    // Acquire crypto provider (use CRYPT_VERIFYCONTEXT since we only do hashing)
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        std::cerr << "CryptAcquireContext failed. Error: " << GetLastError() << std::endl;
        return;
    }

    // Iterate logical drives
    DWORD drives = GetLogicalDrives();
    if (drives == 0)
    {
        std::cerr << "GetLogicalDrives failed. Error: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return;
    }

    for (int i = 0; i < 26; ++i)
    {
        if (!(drives & (1u << i)))
            continue;

        wchar_t driveRoot[] = { static_cast<wchar_t>(L'A' + i), L':', L'\\', L'\0' };
        UINT dtype = GetDriveTypeW(driveRoot);

        // Consider scanning fixed and removable and network drives; skip CD-ROM empty etc.
        if (dtype == DRIVE_FIXED || dtype == DRIVE_REMOVABLE || dtype == DRIVE_REMOTE)
        {
            try
            {
                ScanDirectory_MD5(hProv, std::wstring(driveRoot), MD5HashBlacklist);
            }
            catch (...)
            {
                // continue on unexpected exception
            }
        }
    }

    CryptReleaseContext(hProv, 0);

    std::cout << "Scan finished.\n";
}

bool FileScanner::LoadBlacklist_MD5(const std::string& path)
{
    MD5HashBlacklist.clear();

    return MD5HashMgr.load_db_into_memory(path, MD5HashBlacklist);
}