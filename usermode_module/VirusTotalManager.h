#pragma once
#include "HTTPSManager.h"
#include "MD5_HashManager.h"
#include "ProcessManager.h"
#include "LogsManager.h"

class VirusTotalManager
{
public:
	enum FileAnalysisResult : int8_t
	{
		UNDETECTED = 0,
		MALICIOUS = 1,
		SUSPICIOUS = 2,
		INVALID = 3
	};

private:
	inline static const std::string LogModuleName = "VirusTotal";
	
	std::wstring API_KEY;
	std::wstring hashDatabasePath;
	std::map<MD5_HashManager::Hash16, FileAnalysisResult> localHashDatabase;

public:
	VirusTotalManager(std::wstring API_KEY, _In_opt_ std::wstring hashDatabasePath)
	{
		this->API_KEY = API_KEY;
		if (hashDatabasePath.length() > 0)
			this->hashDatabasePath = hashDatabasePath;
		this->ReadLocalDatabase();
	}

	~VirusTotalManager()
	{
		this->API_KEY.clear();
		this->localHashDatabase.clear();
	}

	bool QueryFileForAnalysis(std::string file_path, _Inout_opt_ std::vector<char>* outResponse, _Inout_opt_ DWORD* outStatusCode);

	bool GetFileAnalysisResult(std::wstring analysisID, _Inout_opt_ std::vector<char>* outResponse);

	bool GetFileReport(std::wstring fileHashHexString, _Inout_opt_ std::vector<char>* outResponse);

	bool AnalyseFileGetResult(std::string file_path, FileAnalysisResult& result);

	bool SaveResultToLocalDatabase(MD5_HashManager::Hash16 Hash, VirusTotalManager::FileAnalysisResult fileAnalysisResult, bool updateMemory = true);

	bool ReadLocalDatabase();

	bool IsHashInLocalDatabase(MD5_HashManager::Hash16 hash, FileAnalysisResult& fileAnalysisResult);

	bool ScanRunningProcessesAndDrivers();
};

