#pragma once
class LogsManager
{
public:
	static std::string GetCurrentDate();

	struct log_entry
	{
		std::string Type = ""; // "Antivirus" - log of detection/action, "UI" - log of options change
		std::string Module_name = ""; // example: "File Scanner", "GUI"
		std::string Date = "";
		std::string Location = "";
		std::string Filename = "";
		std::string Action = "";
		std::string Status = "";
		std::string Description = "";
		std::string Extra_info = "";
	};
	static std::vector<std::unique_ptr<log_entry>> Logs;

private:
	static const uint8_t log_entry_num_of_fields = 9;
	static std::wstring LogsDatabasePath;

public:
	static bool Log(log_entry logEntry, bool Dont_save_to_file = false);

	static bool ExportLogToFile(log_entry Log, std::wstring FilePath = LogsDatabasePath, char SeparatorSign = ';');

	static bool ReadLogsFromFile(std::vector<std::unique_ptr<log_entry>>& LogsList = Logs, std::wstring FilePath = LogsDatabasePath, char SeparatorSign = ';');
};

