#pragma once
class MD5_HashManager
{
private:
    static constexpr size_t RECORD_SIZE = 34; //32 hexstring + \r + newline
    static const DWORD READ_BUFFER_SIZE = 64 * 1024; // 64 KB
public:
    struct Hash16
    {
        uint64_t hi; // bytes 0..7 as big-endian number
        uint64_t lo; // bytes 8..15 as big-endian number

        // Construct from raw 16 bytes (byte[0] is most-significant) (BIG-ENDIAN)
        static Hash16 from_bytes(const unsigned char* b);

        // Parse hex string (may contain whitespace). Return pair(success, Hash16) (BIG-ENDIAN)
        static std::pair<bool, Hash16> from_hexstring(const std::string& s);

        // (BIG-ENDIAN)
        std::string to_hexstring32(); 


        bool operator<(const Hash16& o) const noexcept
        {
            if (hi < o.hi)
                return true;
            if (hi > o.hi)
                return false;
            return lo < o.lo;
        }
        bool operator==(const Hash16& o) const noexcept
        {
            return hi == o.hi && lo == o.lo;
        }
    };

    

    std::vector<Hash16> localHashDatabase;

    bool load_db_into_memory(const std::string& path, std::vector<Hash16>& out);
    bool contains_hash(const std::vector<Hash16>& db, const Hash16& q);

    // Compute MD5 for a file at wide path
    bool computeFileMd5(_In_opt_ HCRYPTPROV hProv, const std::wstring& wfilePath, Hash16& outHex);
};

