#include "pch.h"
#include "ExceptionFilters.h"
#include "LogsManager.h"
#include "ImGUIManager.h"

LONG __stdcall ExceptionFilters::SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	LogsManager::log_entry logentry;
	logentry.Type = "Runtime Exception";
	logentry.Module_name = ModuleName;

	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
	{
		std::stringstream ss;
		ss << "0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress;
		logentry.Location = ss.str();
		logentry.Description = "Exception thrown at: " + ss.str();
		ss.clear();
		ss << "Exception code: " << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode;
		logentry.Extra_info = ss.str();
	}
	else
	{
		logentry.Description = "Exception thrown without exception info";
	}

	// Added for GUI integration
	auto logentryPtr = std::make_unique<LogsManager::log_entry>(logentry);  // Uses default copy constructor of log_entry to initialize with logentry's field values
	ImGUIManager::lQ_mutex.lock();
	ImGUIManager::logQueue.push_back(std::move(logentryPtr));
	ImGUIManager::lQ_mutex.unlock();

	return EXCEPTION_EXECUTE_HANDLER;
}
