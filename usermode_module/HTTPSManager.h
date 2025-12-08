#pragma once

class HTTPSManager
{
public:

    bool HTTPS_sendRequestAndReceiveResponse(std::wstring& hostname, std::wstring& path, std::wstring& HTTPRequestName, _In_opt_ std::wstring* optionalHeaders, _In_opt_ std::string* optionalData,
        _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode);
};



