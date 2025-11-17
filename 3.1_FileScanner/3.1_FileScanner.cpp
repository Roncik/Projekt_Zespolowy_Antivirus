#include "pch.h"
#include "MD5_HashManager.h"
#include "FileScanner.h"
using namespace std;

int main(int argc, char** argv) 
{
    //string dbpath = "C:\\Users\\Administrator\\Desktop\\ProjektZespolowy\\Projekt_Zespolowy_Antivirus\\3.1_FileScanner\\x64\\Release\\merged_hashes.txt"; //VirusShare_00000.md5.txt merged_hashes.txt
    //string qarg = "-";
    //MD5_HashManager hashMgr;

    //vector<MD5_HashManager::Hash16> db;
    //cerr << "Loading DB into memory from '" << dbpath << "' ...\n";
    //if (!hashMgr.load_db_into_memory(dbpath, db))
    //{
    //    cerr << "Failed to load DB\n";
    //    return 2;
    //}
    //cerr << "Loaded " << db.size() << " records (" << (db.size() * hashMgr.RECORD_SIZE) / (1024 * 1024) << " MiB approx)\n";

    //auto process_line = [&](const string& line)
    //    {
    //        pair<bool, MD5_HashManager::Hash16> temp_pair = MD5_HashManager::Hash16::from_hexstring(line);
    //        if (!temp_pair.first)
    //        {
    //            cout << "invalid\n";
    //            return;
    //        }
    //        bool found = hashMgr.contains_hash(db, temp_pair.second);
    //        cout << (found ? "found" : "notfound") << '\n';
    //    };

    //if (qarg == "-") {
    //    string line;
    //    while (getline(cin, line)) {
    //        if (!line.empty()) process_line(line);
    //    }
    //}
    //else {
    //    process_line(qarg);
    //}


    FileScanner fileScanner;
    fileScanner.LoadBlacklist_MD5("C:\\Users\\Administrator\\Desktop\\ProjektZespolowy\\Projekt_Zespolowy_Antivirus\\3.1_FileScanner\\x64\\Release\\merged_hashes.txt");
    fileScanner.ScanAllDirectories_MD5();

    return 0;
}
