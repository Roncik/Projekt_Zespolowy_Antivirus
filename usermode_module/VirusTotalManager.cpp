#include "pch.h"
#include "VirusTotalManager.h"

//static member definitions
const std::string VirusTotalManager::LogModuleName = "VirusTotal"; // VirusTotal

bool VirusTotalManager::QueryFileForAnalysis(std::string file_path, _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode)
{
    if (file_path.length() == 0)
        return false;

    std::string filename = file_path.substr(file_path.find_last_of("/\\"));
    std::ifstream f(file_path, std::ios::binary);
    if (!f)
    {
        return false;
    }

    std::vector<char> file_data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    DWORD file_size = file_data.size();
    

    std::wstring hostname = L"www.virustotal.com";
    std::wstring path = L"/api/v3/files"; 
    std::wstring HTTPRequestName = L"POST";

    HTTPSManager httpsMgr;

    //For files larger than 32MB we need to get a special url for upload
    if (file_size > 32000000 && file_size <= 650000000)
    {
        std::wstring largeUploadPath = L"/api/v3/files/upload_url";
        std::wstring largeUploadHTTPRequestName = L"GET";
        std::wstring headers = L"x-apikey: " + this->API_KEY;
        std::vector<char> response;
        DWORD statusCode = -1;
        httpsMgr.HTTPS_sendRequestAndReceiveResponse(hostname, largeUploadPath, largeUploadHTTPRequestName, &headers, NULL, &response, &statusCode);
        if (statusCode != 200) //status: success
        {
            return false;
        }
        nlohmann::json data = nlohmann::json::parse(response);
        std::string fullpathstr = data["data"];
        std::string pathstr = fullpathstr.substr(fullpathstr.find("virustotal.com") + 14);
        path.assign(pathstr.begin(), pathstr.end());
        hostname = L"bigfiles.virustotal.com";
    }
    else if (file_size > 650000000) //file is too large for analysis
    {
        return false;
    }

    const std::string boundary = "----VTFormBoundary7MA4YWxkTrZu0gW";

    auto utf8_to_wstring = [](const std::string& s) -> std::wstring
        {
            int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
            std::wstring ws(len, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], len);
            return ws;
        };

    // Build multipart body
    std::ostringstream body;
    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n";
    body << "Content-Type: application/octet-stream\r\n\r\n";
    body.write(file_data.data(), file_data.size());
    body << "\r\n--" << boundary << "--\r\n";

    std::string body_str = body.str();

    

    // Build headers
    std::wstring headers = L"x-apikey: " + this->API_KEY + L"\r\n" + utf8_to_wstring("Content-Type: multipart/form-data; boundary=" + boundary);

    DWORD total_size = (DWORD)body_str.size();

    
    bool result = httpsMgr.HTTPS_sendRequestAndReceiveResponse(hostname, path, HTTPRequestName, &headers, &body_str, outResponse, outStatusCode);

    return outStatusCode ? *outStatusCode == 200 && result : result;
}

bool VirusTotalManager::GetFileAnalysisResult(std::wstring analysisID, _Inout_opt_ std::vector<char>* outResponse)
{
    if (analysisID.length() == 0)
        return false;

    std::wstring hostname = L"www.virustotal.com";
    std::wstring path = L"/api/v3/analyses/" + analysisID;
    std::wstring HTTPRequestName = L"GET";
    
    std::wstring headers = L"x-apikey: " + this->API_KEY;
    
    HTTPSManager httpsMgr;

    DWORD requestStatus = -1;
    bool result = httpsMgr.HTTPS_sendRequestAndReceiveResponse(hostname, path, HTTPRequestName, &headers, NULL, outResponse, &requestStatus);

    return requestStatus == 200 && result;
}

bool VirusTotalManager::GetFileReport(std::wstring fileHashHexString, _Inout_opt_ std::vector<char>* outResponse)
{
    if (fileHashHexString.length() == 0)
        return false;

    std::wstring hostname = L"www.virustotal.com";
    std::wstring path = L"/api/v3/files/" + fileHashHexString;
    std::wstring HTTPRequestName = L"GET";

    std::wstring headers = L"x-apikey: " + this->API_KEY;

    HTTPSManager httpsMgr;

    DWORD requestStatus = -1;
    bool result = httpsMgr.HTTPS_sendRequestAndReceiveResponse(hostname, path, HTTPRequestName, &headers, NULL, outResponse, &requestStatus);

    return requestStatus == 200 && result;
}

bool VirusTotalManager::AnalyseFileGetResult(std::string file_path, FileAnalysisResult& result)
{
    //First check if virustotal already has the file in its database
    MD5_HashManager hashMgr;
    std::wstring wfilePath(file_path.begin(), file_path.end());
    MD5_HashManager::Hash16 hash;
    hashMgr.computeFileMd5(NULL, wfilePath, hash);
    std::string hexstring32 = hash.to_hexstring32();
    std::wstring whexstring32(hexstring32.begin(), hexstring32.end());
    std::vector<char> response;
    if (this->GetFileReport(whexstring32, &response)) //File is in virustotal database
    {
        nlohmann::json data = nlohmann::json::parse(response);

        if (data["data"]["attributes"]["last_analysis_stats"]["malicious"] > 10)
            result = VirusTotalManager::FileAnalysisResult::MALICIOUS;
        else if (data["data"]["attributes"]["last_analysis_stats"]["suspicious"] > 10)
            result = VirusTotalManager::FileAnalysisResult::SUSPICIOUS;
        else
            result = VirusTotalManager::FileAnalysisResult::UNDETECTED;

        return true;
    }
    

    DWORD status = -1;
    if (!this->QueryFileForAnalysis(file_path, &response, &status))
        return false;

    nlohmann::json data = nlohmann::json::parse(response);
    std::string analysisIDstr = data["data"]["id"];


    std::wstring analysisID(analysisIDstr.begin(), analysisIDstr.end());
    std::string analysisStatus;
    while (analysisStatus != "completed")
    {
        if (!this->GetFileAnalysisResult(analysisID, &response))
            return false;
        data = nlohmann::json::parse(response);
        analysisStatus = data["data"]["attributes"]["status"];
        Sleep(500);
    }

    if (data["data"]["attributes"]["stats"]["malicious"] > 10)
        result = VirusTotalManager::FileAnalysisResult::MALICIOUS;
    else if (data["data"]["attributes"]["stats"]["suspicious"] > 10)
        result = VirusTotalManager::FileAnalysisResult::SUSPICIOUS;
    else
        result = VirusTotalManager::FileAnalysisResult::UNDETECTED;

    return true;
}

bool VirusTotalManager::SaveResultToLocalDatabase(MD5_HashManager::Hash16 Hash, VirusTotalManager::FileAnalysisResult fileAnalysisResult, bool updateMemory)
{
    /*if (!std::filesystem::exists(this->hashDatabasePath)) 
        return false;*/
    
    std::ofstream database(this->hashDatabasePath, std::ios_base::app);
    if (!database)
        return false;

    database << Hash.to_hexstring32() << ";" << std::to_string(fileAnalysisResult) << "\n"; //entry size = 35bytes
    database.close();
    
    if (updateMemory)
        this->localHashDatabase[Hash] = fileAnalysisResult;

    return true;
}

bool VirusTotalManager::ReadLocalDatabase()
{
    if (!std::filesystem::exists(this->hashDatabasePath))
        return false;

    this->localHashDatabase.clear();

    std::ifstream database(this->hashDatabasePath, std::ios::binary | std::ios::ate);
    if (!database)
        return false;

    std::streamsize fileSize = database.tellg();
    if (fileSize < 0)
        return false;

    static const uint8_t entrySize = 36; //hexstring32 + ';' + uint8_t + \n + \r
    size_t numOfEntries = static_cast<size_t>(fileSize / entrySize);
    database.seekg(0, std::ios::beg); //set cursor to 0
    this->localHashDatabase.clear();
    const size_t BUF_SIZE = entrySize * 50000; // 50000 entries at a time
    std::vector<BYTE> buffer(BUF_SIZE);

    size_t remainingEntries = numOfEntries;
    while (remainingEntries)
    {
        size_t toread_recs = min(remainingEntries, BUF_SIZE / entrySize);
        size_t toread = toread_recs * entrySize;
        database.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(toread));
        if (!database)
            return false;
        
        for (size_t i = 0; i < toread_recs; ++i)
        {
            std::string entry(entrySize + 1, '\0');
            memcpy(entry.data(), buffer.data() + i * entrySize, entrySize);

            MD5_HashManager::Hash16 hash = MD5_HashManager::Hash16::from_hexstring(entry.substr(0, 32)).second;
            VirusTotalManager::FileAnalysisResult analysisResult = static_cast<VirusTotalManager::FileAnalysisResult>(std::stoi(entry.substr(33, 1)));

            this->localHashDatabase[hash] = analysisResult;
        }

        remainingEntries -= toread_recs;
    }
    return true;
}

bool VirusTotalManager::IsHashInLocalDatabase(MD5_HashManager::Hash16 hash, FileAnalysisResult& fileAnalysisResult)
{
    auto it = this->localHashDatabase.find(hash);
    if (it == this->localHashDatabase.end())
        return false;

    fileAnalysisResult = it->second;
    return true;
}

bool VirusTotalManager::ScanRunningProcessesAndDrivers()
{
    ProcessManager procmgr;
    std::vector<ProcessManager::ProcessInfo> processes;
    std::vector<ProcessManager::SystemModuleInfo> systemModules;
    if (!procmgr.GetAllProcesses(processes))
    {
        //std::wcout << L"Failed getting processes!\n";
        return false;
    }

    if (!procmgr.GetAllSystemModules(systemModules))
    {
        //std::wcout << L"Failed getting system modules!\n";
        return false;
    }

    MD5_HashManager hashmgr;


    for (auto& process : processes)
    {
        std::wstring processPath;
        if (!procmgr.GetProcessImagePath(reinterpret_cast<DWORD>(process.processID), processPath))
        {
            //std::wcout << L"Failed getting path for process: " << process.processName << L"\n";
            continue;
        }

        MD5_HashManager::Hash16 processFileHash;
        if (!hashmgr.computeFileMd5(NULL, processPath, processFileHash))
        {
            //std::wcout << L"Failed getting hash for process: " << process.processName << L"\n";
            continue;
        }

        VirusTotalManager::FileAnalysisResult result;

        //std::wcout << L"Now scanning: " << process.processName << L" - ";
        if (!this->IsHashInLocalDatabase(processFileHash, result)) //file was already scanned before
        {
            std::string processPathStr(processPath.begin(), processPath.end());


            if (!this->AnalyseFileGetResult(processPathStr, result))
            {
                //std::wcout << L"file analysis failed\n";
                continue;
            }
            this->SaveResultToLocalDatabase(processFileHash, result, true);
        }

        LogsManager::log_entry logentry;
        logentry.Module_name = VirusTotalManager::LogModuleName;
        logentry.Filename = std::string(process.processName.begin(), process.processName.end());
        logentry.Location = std::string(processPath.begin(), processPath.end());
        logentry.Status = "Analysis finished";
        logentry.Description = "This file was sucessfully analysed using VirusTotal API";
        logentry.Extra_info = "File's MD5 Hash: " + processFileHash.to_hexstring32();

        if (result == VirusTotalManager::FileAnalysisResult::MALICIOUS)
            logentry.Type = "Malicious file";
        else if (result == VirusTotalManager::FileAnalysisResult::SUSPICIOUS)
            logentry.Type = "Suspicious file";

        LogsManager::Log(logentry);
    }

    for (auto& systemModule : systemModules)
    {
        std::wstring Path = systemModule.filePath;


        MD5_HashManager::Hash16 processFileHash;
        if (!hashmgr.computeFileMd5(NULL, Path, processFileHash))
        {
            //std::wcout << L"Failed getting hash for process: " << systemModule.fileName << L"\n";
            continue;
        }

        VirusTotalManager::FileAnalysisResult result;

        std::wcout << L"Now scanning: " << systemModule.fileName << L" - ";
        if (!this->IsHashInLocalDatabase(processFileHash, result))
        {
            std::string processPathStr(Path.begin(), Path.end());

            if (!this->AnalyseFileGetResult(processPathStr, result))
            {
                //std::wcout << L"file analysis failed\n";
                continue;
            }
            this->SaveResultToLocalDatabase(processFileHash, result, true);
        }

        LogsManager::log_entry logentry;
        logentry.Module_name = VirusTotalManager::LogModuleName;
        logentry.Filename = std::string(systemModule.fileName.begin(), systemModule.fileName.end());
        logentry.Location = std::string(Path.begin(), Path.end());
        logentry.Status = "Analysis finished";
        logentry.Description = "This file was sucessfully analysed using VirusTotal API";
        logentry.Extra_info = "File's MD5 Hash: " + processFileHash.to_hexstring32();

        if (result == VirusTotalManager::FileAnalysisResult::MALICIOUS)
            logentry.Type = "Malicious file";
        else if (result == VirusTotalManager::FileAnalysisResult::SUSPICIOUS)
            logentry.Type = "Suspicious file";

        LogsManager::Log(logentry);
    }

    return true;
}

