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

		std::string ToString()
		{
			std::stringstream output;
			output << "Type: " << Type << std::endl;
			output << "Module_name: " << Module_name << std::endl;
			output << "Date: " << Date << std::endl;
			output << "Location: " << Location << std::endl;
			output << "Filename: " << Filename << std::endl;
			output << "Action: " << Action << std::endl;
			output << "Status: " << Status << std::endl;
			output << "Description: " << Description << std::endl;
			output << "Extra_info: " << Extra_info << std::endl;
			return output.str();
		}
	};
	inline static std::vector<std::unique_ptr<log_entry>> Logs;

private:
	static const uint8_t log_entry_num_of_fields = 9;
	inline static std::wstring LogsDatabasePath = L"logs.txt";

public:
	static bool Log(log_entry logEntry, bool Dont_save_to_file = false);

	static bool ExportLogToFile(log_entry Log, std::wstring FilePath = LogsDatabasePath, char SeparatorSign = ';');

	static bool ReadLogsFromFile(std::vector<std::unique_ptr<log_entry>>& LogsList = Logs, std::wstring FilePath = LogsDatabasePath, char SeparatorSign = ';');
};

