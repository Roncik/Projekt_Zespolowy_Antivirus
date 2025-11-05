//#include <iostream>
//#include <windows.h>
//#include <vector>
//#include <fstream>
//#include <string>
//#include <algorithm>
//
//static constexpr size_t RECORD_SIZE = 33; //32 hexstring + newline
//
//struct Hash16
//{
//    uint64_t hi; // bytes 0..7 as big-endian number
//    uint64_t lo; // bytes 8..15 as big-endian number
//
//    // Construct from raw 16 bytes (byte[0] is most-significant)
//    static Hash16 from_bytes_be(const unsigned char* b)
//    {
//        Hash16 h;
//        uint64_t a = 0;
//        for (int i = 0; i < 8; ++i) { a = (a << 8) | (uint64_t)b[i]; }
//        uint64_t c = 0;
//        for (int i = 0; i < 8; ++i) { c = (c << 8) | (uint64_t)b[8 + i]; }
//        h.hi = a;
//        h.lo = c;
//        return h;
//    }
//
//    // Parse hex string (may contain whitespace). Return pair(success, Hash16)
//    static std::pair<bool, Hash16> from_hexstring(const std::string& s)
//    {
//        unsigned char bytes[16];
//        int nibble_count = 0;
//        int byte_idx = 0;
//        int cur = 0;
//        bool have_hi_nibble = false;
//        for (char ch : s)
//        {
//            int v = -1;
//            if (ch >= '0' && ch <= '9') v = ch - '0';
//            else if (ch >= 'a' && ch <= 'f') v = 10 + (ch - 'a');
//            else if (ch >= 'A' && ch <= 'F') v = 10 + (ch - 'A');
//            else continue; // ignore whitespace/other
//            if (!have_hi_nibble)
//            {
//                cur = v << 4;
//                have_hi_nibble = true;
//            }
//            else
//            {
//                cur |= v;
//                if (byte_idx >= (int)16) return { false, {} };
//                bytes[byte_idx++] = (unsigned char)cur;
//                cur = 0;
//                have_hi_nibble = false;
//            }
//        }
//        if (byte_idx != (int)16)
//            return { false, {} };
//        return { true, from_bytes_be(bytes) };
//    }
//
//    bool operator<(const Hash16& o) const noexcept
//    {
//        if (hi < o.hi) return true;
//        if (hi > o.hi) return false;
//        return lo < o.lo;
//    }
//    bool operator==(const Hash16& o) const noexcept
//    {
//        return hi == o.hi && lo == o.lo;
//    }
//};
//
//bool load_db_into_memory(const std::string& path, std::vector<Hash16>& out)
//{
//    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
//    if (!ifs)
//    {
//        std::cerr << "ERROR: cannot open file: " << path << "\n";
//        return false;
//    }
//
//    std::streamsize sz = ifs.tellg();
//    if (sz < 0)
//    {
//        std::cerr << "ERROR: bad file size\n"; return false;
//    }
//
//    if (sz % (std::streamsize)RECORD_SIZE != 0)
//    {
//        std::cerr << "ERROR: file size not a multiple of " << RECORD_SIZE << "\n";
//        return false;
//    }
//
//
//    size_t n = (size_t)(sz / RECORD_SIZE);
//    ifs.seekg(0, std::ios::beg);
//
//    // Reserve vector capacity then read in big blocks for efficiency
//    out.clear();
//    out.reserve(n);
//
//    const size_t BUF_RECS = 1 << 16; // number of records per chunk (~65536)
//    const size_t BUF_BYTES = BUF_RECS * RECORD_SIZE;
//    std::vector<char> buffer;
//    buffer.resize(BUF_BYTES);
//
//    size_t remaining = n;
//    while (remaining > 0)
//    {
//        size_t to_read_recs = min(remaining, BUF_RECS);
//        size_t to_read_bytes = to_read_recs * RECORD_SIZE;
//        ifs.read(buffer.data(), (std::streamsize)to_read_bytes);
//        if (!ifs)
//        {
//            std::cerr << "ERROR: read failed\n";
//            return false;
//        }
//        // convert each record to Hash16
//        for (size_t i = 0; i < to_read_recs; ++i)
//        {
//            unsigned char* rec = (unsigned char*)(buffer.data() + i * RECORD_SIZE);
//            char hexStringBytes[RECORD_SIZE + 1] = { 0 };
//            memcpy(&hexStringBytes, rec, RECORD_SIZE);
//            out.push_back(Hash16::from_hexstring(hexStringBytes).second);
//        }
//        remaining -= to_read_recs;
//    }
//    return true;
//}
//
//bool contains_hash(const std::vector<Hash16>& db, const Hash16& q)
//{
//    return (std::find(db.begin(), db.end(), q) != db.end());
//}