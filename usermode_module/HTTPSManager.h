#pragma once

class HTTPSManager
{
public:


    // Build Authorization header: "Authorization: Bearer <key>"
    //    std::wstring authHeader = L"Authorization: Bearer ";
    //    authHeader += api_key;
    // API key (keep secret).
    //    const std::wstring api_key = L"YOUR_API_KEY_HERE";
    bool HTTPS_sendRequestAndReceiveResponse(std::wstring& hostname, std::wstring& path, std::wstring& HTTPRequestName, _In_opt_ std::wstring* optionalHeaders,
        _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode);
    
};

