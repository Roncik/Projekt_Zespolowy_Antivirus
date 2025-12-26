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
    // helper to convert a single hex digit to value or -1 if invalid
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
        };

    // remove whitespace
    std::string filtered;
    filtered.reserve(s.size());
    for (unsigned char ch : s) {
        if (!std::isspace(ch)) filtered.push_back(static_cast<char>(ch));
    }

    // optional 0x/0X prefix
    if (filtered.size() >= 2 && filtered[0] == '0' && (filtered[1] == 'x' || filtered[1] == 'X')) {
        filtered.erase(0, 2);
    }

    // must be exactly 32 hex digits for an MD5 (16 bytes)
    if (filtered.size() != 32) {
        return { false, Hash16{} };
    }

    unsigned char bytes[16];
    for (size_t i = 0; i < 16; ++i) {
        int hi = hexval(filtered[2 * i]);
        int lo = hexval(filtered[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return { false, Hash16{} };
        }
        bytes[i] = static_cast<unsigned char>((hi << 4) | lo);
    }

    // interpret bytes[0..7] as big-endian into hi, bytes[8..15] as big-endian into lo
    uint64_t hi64 = 0;
    for (size_t i = 0; i < 8; ++i) {
        hi64 = (hi64 << 8) | uint64_t(bytes[i]);
    }
    uint64_t lo64 = 0;
    for (size_t i = 8; i < 16; ++i) {
        lo64 = (lo64 << 8) | uint64_t(bytes[i]);
    }

    Hash16 h;
    h.hi = hi64;
    h.lo = lo64;
    return { true, h };
}

std::string MD5_HashManager::Hash16::to_hexstring32()
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);

    // hi: bytes 0..7 (most-significant first)
    for (int i = 7; i >= 0; --i) {
        unsigned int byte = static_cast<unsigned int>((hi >> (i * 8)) & 0xFFu);
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0F]);
    }

    // lo: bytes 8..15 (most-significant first)
    for (int i = 7; i >= 0; --i) {
        unsigned int byte = static_cast<unsigned int>((lo >> (i * 8)) & 0xFFu);
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0F]);
    }

    return out;
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
            std::string entry(RECORD_SIZE+1, '\0');
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
bool MD5_HashManager::computeFileMd5(_In_opt_ HCRYPTPROV hProv, const std::wstring& wfilePath, MD5_HashManager::Hash16& outHex) 
{
    HCRYPTPROV prov;
    if (!hProv)
    {
        if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            return false;
        }
    }
    else
        prov = hProv;
    
    
    HCRYPTHASH hHash = 0;

    if (!CryptCreateHash(prov, CALG_MD5, 0, 0, &hHash)) 
    {
        // failed to create hash
        if (!hProv) 
            CryptReleaseContext(prov, 0);
        return false;
    }

    // Open file for reading
    // To support long paths, prefix with \\?\ if needed
    std::wstring pathWithPrefix = wfilePath;
    if (pathWithPrefix.size() >= MAX_PATH) 
    {
        if (pathWithPrefix.rfind(L"\\\\?\\", 0) != 0) 
        {
            // For UNC paths beginning with \\ add UNC form
            if (pathWithPrefix.rfind(L"\\\\", 0) == 0) 
            {
                pathWithPrefix = L"\\\\?\\UNC" + pathWithPrefix.substr(1); // replace leading "\\" with "\\?\UNC\"
            }
            else {
                pathWithPrefix = L"\\\\?\\" + pathWithPrefix;
            }
        }
    }

    HANDLE hFile = CreateFileW(pathWithPrefix.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) 
    {
        CryptDestroyHash(hHash);
        if (!hProv)
            CryptReleaseContext(prov, 0);
        return false;
    }

    std::vector<BYTE> buffer(MD5_HashManager::READ_BUFFER_SIZE);
    DWORD bytesRead = 0;
    BOOL readOK = TRUE;
    while (ReadFile(hFile, buffer.data(), (DWORD)buffer.size(), &bytesRead, nullptr) && bytesRead > 0) 
    {
        if (!CryptHashData(hHash, buffer.data(), bytesRead, 0)) 
        {
            readOK = FALSE;
            break;
        }
    }

    CloseHandle(hFile);

    if (!readOK) 
    {
        CryptDestroyHash(hHash);
        if (!hProv)
            CryptReleaseContext(prov, 0);
        return false;
    }

    // Get hash size
    DWORD hashLen = 0;
    DWORD cbHashLen = sizeof(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &cbHashLen, 0)) 
    {
        // fallback: try HP_HASHVAL directly
        hashLen = 16; // MD5 fixed length
    }

    std::vector<BYTE> hashBytes(hashLen);
    DWORD cbHashBytes = (DWORD)hashBytes.size();
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &cbHashBytes, 0)) 
    {
        CryptDestroyHash(hHash);
        if (!hProv)
            CryptReleaseContext(prov, 0);
        return false;
    }

    memcpy(&outHex, hashBytes.data(), hashLen);

    //Convert output to big-endian from little-endian
    outHex.hi = _byteswap_uint64(outHex.hi);
    outHex.lo = _byteswap_uint64(outHex.lo);

    CryptDestroyHash(hHash);
    if (!hProv)
        CryptReleaseContext(prov, 0);
    return true;
}
