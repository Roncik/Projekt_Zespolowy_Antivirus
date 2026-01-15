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

bool LogsManager::Log(log_entry logEntry, bool Dont_save_to_file)
{
    if (!Dont_save_to_file)
    {
        if (!LogsManager::ExportLogToFile(logEntry))
            return false;
    }

    LogsManager::Logs.push_back(logEntry);
    
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
