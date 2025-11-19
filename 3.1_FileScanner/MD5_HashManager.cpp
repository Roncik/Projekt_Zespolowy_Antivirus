#include "pch.h"
#include "MD5_HashManager.h"
using namespace std;

MD5_HashManager::Hash16 MD5_HashManager::Hash16::from_bytes(const unsigned char* b)
{
    Hash16 h;
    uint64_t a = 0;
    for (int i = 0; i < 8; ++i) { a = (a << 8) | (uint64_t)b[i]; }
    uint64_t c = 0;
    for (int i = 0; i < 8; ++i) { c = (c << 8) | (uint64_t)b[8 + i]; }
    h.hi = a;
    h.lo = c;
    return h;
}

pair<bool, MD5_HashManager::Hash16> MD5_HashManager::Hash16::from_hexstring(const string& s)
{
    unsigned char bytes[16];
    int nibble_count = 0;
    int byte_idx = 0;
    int cur = 0;
    bool have_hi_nibble = false;
    for (char ch : s)
    {
        int v = -1;
        if (ch >= '0' && ch <= '9') v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = 10 + (ch - 'a');
        else if (ch >= 'A' && ch <= 'F') v = 10 + (ch - 'A');
        else continue; // ignore whitespace/other
        if (!have_hi_nibble)
        {
            cur = v << 4;
            have_hi_nibble = true;
        }
        else
        {
            cur |= v;
            if (byte_idx >= (int)16) return { false, {} };
            bytes[byte_idx++] = (unsigned char)cur;
            cur = 0;
            have_hi_nibble = false;
        }
    }
    if (byte_idx != (int)16)
        return { false, {} };
    return { true, from_bytes(bytes) };
}

bool MD5_HashManager::load_db_into_memory(const string& path, vector<Hash16>& out)
{
    ifstream ifs(path, ios::binary | ios::ate); //ios::binary | ios::ate
    if (!ifs)
    {
        cerr << "ERROR: cannot open file: " << path << "\n";
        return false;
    }

    streamsize fileSize = ifs.tellg();
    if (fileSize < 0)
    {
        cerr << "ERROR: bad file size\n"; return false;
    }

    size_t numOfEntries = static_cast<size_t>(fileSize / RECORD_SIZE);
    ifs.seekg(0, ios::beg); //set cursor to 0
    out.clear();
    out.reserve(numOfEntries);
    const size_t BUF_SIZE = RECORD_SIZE * 50000; // 50000 entries at a time
    vector<char> buffer(BUF_SIZE);
    size_t remainingEntries = numOfEntries;
    while (remainingEntries)
    {
        size_t toread_recs = min(remainingEntries, BUF_SIZE / RECORD_SIZE);
        size_t toread = toread_recs * RECORD_SIZE;
        ifs.read(buffer.data(), (streamsize)toread);
        if (!ifs)
        {
            cerr << "ERROR: read failed\n";
            return false;
        }
        for (int i = 0; i < toread_recs; i++)
        {
            std::string entry;
            entry.resize(34);
            memcpy(entry.data(), buffer.data() + i * RECORD_SIZE, RECORD_SIZE);
            out.push_back(Hash16::from_hexstring(entry).second);
        }

        remainingEntries -= toread_recs;
    }
    return true;
}

bool MD5_HashManager::contains_hash(const std::vector<Hash16>& db, const Hash16& q)
{
    return (std::find(db.begin(), db.end(), q) != db.end());
}

// Compute MD5 for a file at wide path.
bool MD5_HashManager::computeFileMd5(HCRYPTPROV hProv, const std::wstring& wfilePath, MD5_HashManager::Hash16& outHex) 
{
    HCRYPTPROV prov = hProv;
    HCRYPTHASH hHash = 0;

    if (!CryptCreateHash(prov, CALG_MD5, 0, 0, &hHash)) {
        // failed to create hash
        return false;
    }

    // Open file for reading
    // To support long paths, prefix with \\?\ if needed
    std::wstring pathWithPrefix = wfilePath;
    if (pathWithPrefix.size() >= MAX_PATH) {
        if (pathWithPrefix.rfind(L"\\\\?\\", 0) != 0) {
            // For UNC paths beginning with \\ add UNC form
            if (pathWithPrefix.rfind(L"\\\\", 0) == 0) {
                pathWithPrefix = L"\\\\?\\UNC" + pathWithPrefix.substr(1); // replace leading "\\" with "\\?\UNC\"
            }
            else {
                pathWithPrefix = L"\\\\?\\" + pathWithPrefix;
            }
        }
    }

    HANDLE hFile = CreateFileW(
        pathWithPrefix.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        CryptDestroyHash(hHash);
        return false;
    }

    std::vector<BYTE> buffer(MD5_HashManager::READ_BUFFER_SIZE);
    DWORD bytesRead = 0;
    BOOL readOK = TRUE;
    while (ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, nullptr) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer.data(), bytesRead, 0)) {
            readOK = FALSE;
            break;
        }
    }

    CloseHandle(hFile);

    if (!readOK) {
        CryptDestroyHash(hHash);
        return false;
    }

    // Get hash size
    DWORD hashLen = 0;
    DWORD cbHashLen = sizeof(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &cbHashLen, 0)) {
        // fallback: try HP_HASHVAL directly
        hashLen = 16; // MD5 fixed length
    }

    std::vector<BYTE> hashBytes(hashLen);
    DWORD cbHashBytes = (DWORD)hashBytes.size();
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &cbHashBytes, 0)) {
        CryptDestroyHash(hHash);
        return false;
    }

    memcpy(&outHex, hashBytes.data(), hashLen);

    CryptDestroyHash(hHash);
    return true;
}
