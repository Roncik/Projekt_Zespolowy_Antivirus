#pragma once
class SignatureManager
{
public:
    // convert hex string (with optional '?' wildcard) to pattern+mask
    void ParseHexPattern(const std::string& hex, std::vector<BYTE>& outBytes, std::string& outMask);

    // naive search with mask
    uintptr_t FindPattern(const BYTE* data, SIZE_T dataLen, const std::vector<BYTE>& pattern, const std::string& mask);
};

