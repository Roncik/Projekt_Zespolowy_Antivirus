#include "pch.h"
#include "LogsManager.h"

//static member definitions
std::vector<LogsManager::log_entry> LogsManager::Logs;
std::wstring LogsManager::LogsDatabasePath = L"logs.txt";

std::string LogsManager::GetCurrentDate()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    std::time_t tt = system_clock::to_time_t(now);

    std::tm tm;
    localtime_s(&tm, &tt);

    std::ostringstream oss;

    oss << std::put_time(&tm, "%Y/%m/%d %H:%M"); // YYYY/mm/dd HH:MM
    return oss.str();
}

bool LogsManager::Log(std::string Type, std::string Module_name, bool Dont_save_to_file, std::optional<std::string> Date, std::optional<std::string> Location, std::optional<std::string> Filename,
    std::optional<std::string> Action, std::optional<std::string> Status, std::optional<std::string> Description, std::optional<std::string> Extra_info)
{
    LogsManager::log_entry entry = 
    {
    Type,
    Module_name,
    Date ? *Date : this->GetCurrentDate(),
    Location ? *Location : "",
    Filename ? *Filename : "",
    Action ? *Action : "",
    Status ? *Status : "",
    Description ? *Description : "",
    Extra_info ? *Extra_info : ""
    };

    if (!Dont_save_to_file)
    {
        if (!this->ExportLogToFile(entry))
            return false;
    }

    LogsManager::Logs.push_back(entry);
    
    return true;
}

bool LogsManager::ExportLogToFile(log_entry Log, std::wstring FilePath, char SeparatorSign)
{
    std::ofstream database(FilePath, std::ios_base::app);
    if (!database)
        return false;

    database << Log.Type << SeparatorSign << Log.Module_name << SeparatorSign << Log.Date << SeparatorSign
             << Log.Location << SeparatorSign << Log.Filename << SeparatorSign << Log.Action << SeparatorSign 
             << Log.Status << SeparatorSign << Log.Description << SeparatorSign << Log.Extra_info << SeparatorSign << "\n";
    database.close();

    return true;

}

bool LogsManager::ReadLogsFromFile(std::vector<log_entry>& LogsList, std::wstring FilePath, char SeparatorSign)
{
    std::ifstream database(FilePath);
    if (!database)
        return false;

    for (std::string line; std::getline(database, line); )
    {
        std::vector<std::string> fields;
        
        size_t pos = 0;
        while (pos != std::string_view::npos)
        {
            size_t next = line.find(SeparatorSign, pos);
            if (next == std::string_view::npos)
                break;

            fields.push_back(line.substr(pos, next - pos));
            pos = pos == next ? pos + 1 : next + 1;
        }

        if (fields.size() != LogsManager::log_entry_num_of_fields)
            continue;

        LogsList.push_back({fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8]});
    }
    
    return true;
}
