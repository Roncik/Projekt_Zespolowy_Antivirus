#pragma once
class SignatureManager
{
public:
    static std::vector<std::pair<std::string, std::wstring>> CodeSignatureDatabase;

    // convert hex string (with optional '?' wildcard) to pattern+mask
    void ParseHexPattern(const std::string& hex, std::vector<BYTE>& outBytes, std::string& outMask);

    // naive search with mask
    uintptr_t FindPattern(const BYTE* data, SIZE_T dataLen, const std::vector<BYTE>& pattern, const std::string& mask);

    
    static void AddCodeSignatureToDatabase(std::pair<std::string, std::wstring>& codeSignature);
};

