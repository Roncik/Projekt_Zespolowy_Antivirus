#pragma once
class ExceptionFilters
{
	inline static std::string ModuleName = "Exception Handler";
public:
	static LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo);
};

