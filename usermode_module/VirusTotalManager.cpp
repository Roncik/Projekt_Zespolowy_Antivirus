#include "pch.h"
#include "VirusTotalManager.h"
#include "HTTPSManager.h"

bool VirusTotalManager::QueryFileForAnalysis(std::string file_path, _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode)
{
    if (file_path.length() == 0)
        return false;
    
    HTTPSManager httpsMgr;

    std::wstring hostname = L"www.virustotal.com";
    std::wstring path = L"/api/v3/files"; 
    std::wstring HTTPRequestName = L"POST";

    std::string filename = file_path.substr(file_path.find_last_of("/\\"));
    std::ifstream f(file_path, std::ios::binary);
    if (!f) 
    {
        return false;
    }

    std::vector<char> file_data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();

    // Build multipart body
    const std::string boundary = "----VTFormBoundary7MA4YWxkTrZu0gW";

    std::ostringstream body;
    body << "--" << boundary << "\r\n";
    body << "Content-Disposition: form-data; name=\"file\"; filename=\"" << filename << "\"\r\n";
    body << "Content-Type: application/octet-stream\r\n\r\n";
    body.write(file_data.data(), file_data.size());
    body << "\r\n--" << boundary << "--\r\n";

    std::string body_str = body.str();

    auto utf8_to_wstring = [](const std::string & s) -> std::wstring
        {
            int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
            std::wstring ws(len, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], len);
            return ws;
        };

    // Build proper headers (IMPORTANT)
    std::wstring headers = L"x-apikey: " + this->API_KEY + L"\r\n" + utf8_to_wstring("Content-Type: multipart/form-data; boundary=" + boundary);

    DWORD total_size = (DWORD)body_str.size();

    return httpsMgr.HTTPS_sendRequestAndReceiveResponse(hostname, path, HTTPRequestName, &headers, &body_str, outResponse, outStatusCode);
}

bool VirusTotalManager::GetFileAnalysisResult(std::wstring analysisID, _Inout_opt_ std::vector<char>* outResponse)
{
    if (analysisID.length() == 0)
        return false;
    
    HTTPSManager httpsMgr;

    std::wstring hostname = L"www.virustotal.com";
    std::wstring path = L"/api/v3/analyses/" + analysisID;
    std::wstring HTTPRequestName = L"GET";
    
    std::wstring headers = L"x-apikey: " + this->API_KEY;
    
    return httpsMgr.HTTPS_sendRequestAndReceiveResponse(hostname, path, HTTPRequestName, &headers, NULL, outResponse, NULL);;
}

