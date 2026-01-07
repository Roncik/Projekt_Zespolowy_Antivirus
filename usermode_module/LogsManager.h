#pragma once
class LogsManager
{
private:
	struct log_entry
	{
		std::string Type;
		std::string Module_name;
		std::string Date;
		std::string Location;
		std::string Filename;
		std::string Action;
		std::string Status;
		std::string Description;
		std::string Extra_info;
	};
	static const uint8_t log_entry_num_of_fields = 9;

	static std::vector<log_entry> Logs;
	static std::wstring LogsDatabasePath;

public:
	std::string GetCurrentDate();

	bool Log(std::string Type, std::string Module_name, bool Dont_save_to_file = false, std::optional<std::string> Date = std::nullopt, 
		std::optional<std::string> Location = std::nullopt, std::optional<std::string> Filename = std::nullopt,
		std::optional<std::string> Action = std::nullopt, std::optional<std::string> Status = std::nullopt, 
		std::optional<std::string> Description = std::nullopt, std::optional<std::string> Extra_info = std::nullopt);

	bool ExportLogToFile(log_entry Log, std::wstring FilePath = LogsDatabasePath, char SeparatorSign = ';');

	bool ReadLogsFromFile(std::vector<log_entry>& LogsList = Logs, std::wstring FilePath = LogsDatabasePath, char SeparatorSign = ';');
};

