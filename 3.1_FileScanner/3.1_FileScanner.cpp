#include <iostream>
#include <windows.h>
#include <vector>
#include <fstream>
#include <string>
using namespace std;

static constexpr size_t RECORD_SIZE = 34; //32 hexstring + newline

struct Hash16 
{
    uint64_t hi; // bytes 0..7 as big-endian number
    uint64_t lo; // bytes 8..15 as big-endian number

    // Construct from raw 16 bytes (byte[0] is most-significant)
    static Hash16 from_bytes(const unsigned char* b) 
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

    // Parse hex string (may contain whitespace). Return pair(success, Hash16)
    static pair<bool, Hash16> from_hexstring(const string& s) 
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

    bool operator<(const Hash16& o) const noexcept 
    {
        if (hi < o.hi) return true;
        if (hi > o.hi) return false;
        return lo < o.lo;
    }
    bool operator==(const Hash16& o) const noexcept 
    {
        return hi == o.hi && lo == o.lo;
    }
};

bool load_db_into_memory(const string& path, vector<Hash16>& out)
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
    const size_t BUF_SIZE = RECORD_SIZE*50000; // 50000 entries at a time
    vector<char> buffer(BUF_SIZE * RECORD_SIZE);
    size_t remainingEntries = numOfEntries;
    while (remainingEntries)
    {
        size_t toread_recs = min(remainingEntries, BUF_SIZE);
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

bool contains_hash(const std::vector<Hash16>& db, const Hash16& q)
{
    return (std::find(db.begin(), db.end(), q) != db.end());
}


int main(int argc, char** argv) 
{
    string dbpath = "C:\\Users\\Administrator\\Desktop\\ProjektZespolowy\\Projekt_Zespolowy_Antivirus\\3.1_FileScanner\\x64\\Release\\merged_hashes.txt"; //VirusShare_00000.md5.txt merged_hashes.txt
    string qarg = "-";

    vector<Hash16> db;
    cerr << "Loading DB into memory from '" << dbpath << "' ...\n";
    if (!load_db_into_memory(dbpath, db)) 
    {
        cerr << "Failed to load DB\n";
        return 2;
    }
    cerr << "Loaded " << db.size() << " records (" << (db.size() * RECORD_SIZE) / (1024 * 1024) << " MiB approx)\n";

    auto process_line = [&](const string& line)
        {
            pair<bool, Hash16> temp_pair = Hash16::from_hexstring(line);
            if (!temp_pair.first)
            {
                cout << "invalid\n";
                return;
            }
            bool found = contains_hash(db, temp_pair.second);
            cout << (found ? "found" : "notfound") << '\n';
        };

    if (qarg == "-") {
        string line;
        while (getline(cin, line)) {
            if (!line.empty()) process_line(line);
        }
    }
    else {
        process_line(qarg);
    }

    return 0;
}
