#include "pch.h"
#include "VirusTotalManager.h"
#include "HTTPSManager.h"

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

bool VirusTotalManager::AnalyseFileGetResult(std::string file_path, FileAnalysisResult& result)
{
    std::vector<char> response;
    DWORD status = -1;
    if (!this->QueryFileForAnalysis(file_path, &response, &status))
        return false;

    nlohmann::json data = nlohmann::json::parse(response);
    std::string analysisIDstr = data["data"]["id"];


    std::wstring analysisID(analysisIDstr.begin(), analysisIDstr.end());
    std::string analysisStatus;
    while (analysisStatus != "completed")
    {
        this->GetFileAnalysisResult(analysisID, &response);
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

