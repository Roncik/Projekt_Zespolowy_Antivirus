#pragma once

class VirusTotalManager
{
private:
	std::wstring API_KEY;

public:
	VirusTotalManager(std::wstring API_KEY)
	{
		this->API_KEY = API_KEY;
	}

	~VirusTotalManager()
	{
		this->API_KEY.clear();
	}

	bool QueryFileForAnalysis(std::string file_path, _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode);

	bool GetFileAnalysisResult(std::wstring analysisID, _Inout_opt_ std::vector<char>* outResponse);
};

