#include "pch.h"
#include "HTTPSManager.h"

bool HTTPSManager::HTTPS_sendRequestAndReceiveResponse(std::wstring& hostname, std::wstring& path, std::wstring& HTTPRequestName, _In_opt_ std::wstring* optionalHeaders, _In_opt_ std::string* optionalData,
    _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode)
{
    if (hostname.length() == 0 || path.length() == 0 || HTTPRequestName.length() == 0)
    {
        return false;
    }

    HINTERNET hSession = WinHttpOpen(L"WinHTTP-Client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, hostname.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, HTTPRequestName.c_str(), path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    BOOL bRequestResult = WinHttpSendRequest(hRequest, optionalHeaders ? optionalHeaders->c_str() : 0, optionalHeaders ? static_cast<DWORD>(optionalHeaders->size()) : 0,
        optionalData ? static_cast<LPVOID>(optionalData->data()) : 0, optionalData ? optionalData->length() : 0, optionalData ? static_cast<DWORD>(optionalData->length()) : 0, NULL);

    if (!bRequestResult)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        WinHttpCloseHandle(hRequest);
        return false;
    }

    BOOL bResponseResult = WinHttpReceiveResponse(hRequest, nullptr);
    if (!bResponseResult)
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Status code
    if (outStatusCode)
    {
        DWORD statusCode = 0;
        DWORD statusSize = sizeof(statusCode);
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX))
            *outStatusCode = statusCode;
    }

    if (outResponse)
    {
        outResponse->clear();
        
        // Read response
        std::vector<char> responseData;
        for (;;)
        {
            DWORD availableDataSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &availableDataSize))
            {
                std::cerr << "WinHttpQueryDataAvailable failed: " << GetLastError() << "\n";
                break;
            }

            if (availableDataSize == 0)
                break; // no more data

            std::vector<char> buffer(availableDataSize);
            DWORD bytesRead = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), availableDataSize, &bytesRead))
            {
                std::cerr << "WinHttpReadData failed: " << GetLastError() << "\n";
                break;
            }
            outResponse->insert(outResponse->end(), buffer.data(), buffer.data() + bytesRead);
        }
    }

    // Clean up
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return true;
}