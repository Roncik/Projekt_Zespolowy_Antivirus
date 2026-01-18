#include "pch.h"
#include "SignatureManager.h"

//static member definitions
std::vector<std::pair<std::string, std::wstring>> SignatureManager::CodeSignatureDatabase;

void SignatureManager::ParseHexPattern(const std::string& hex, std::vector<BYTE>& outBytes, std::string& outMask)
{
    outBytes.clear();
    outMask.clear();
    size_t i = 0;
    while (i < hex.size())
    {
        if (hex[i] == ' ')
        {
            ++i;
            continue;
        }
        if (hex[i] == '?')
        {
            // wildcard for single nibble or whole byte; support "?" or "??"
            if (i + 1 < hex.size() && hex[i + 1] == '?') 
                ++i;
            outBytes.push_back(0x00);
            outMask.push_back('?');
            ++i;
            continue;
        }
        // read two hex chars
        if (i + 1 >= hex.size()) break;
        char a = hex[i];
        char b = hex[i + 1];
        auto hexval = [](char c)->int 
            {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
            };
        int va = hexval(a);
        int vb = hexval(b);
        if (va < 0 || vb < 0) 
        { 
            i += 2; 
            continue; 
        }
        outBytes.push_back((BYTE)((va << 4) | vb));
        outMask.push_back('x');
        i += 2;
    }
}

uintptr_t SignatureManager::FindPattern(const BYTE* data, SIZE_T dataLen, const std::vector<BYTE>& pattern, const std::string& mask)
{
    if (pattern.empty() || mask.size() != pattern.size() || dataLen < pattern.size()) 
        return 0;
    for (SIZE_T i = 0; i + pattern.size() <= dataLen; ++i)
    {
        bool ok = true;
        for (SIZE_T j = 0; j < pattern.size(); ++j)
        {
            if (mask[j] == 'x' && data[i + j] != pattern[j]) 
            { 
                ok = false; 
                break; 
            }
        }
        if (ok) 
            return (uintptr_t)(i); //returns an offset to the first byte of the first pattern instance in the data
    }
    return 0;
}

void SignatureManager::AddCodeSignatureToDatabase(std::pair<std::string, std::wstring>& codeSignature)
{
    SignatureManager::CodeSignatureDatabase.push_back(codeSignature);
}

