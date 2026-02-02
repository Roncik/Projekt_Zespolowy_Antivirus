#pragma once

class moduleDeployer
{
public:
    static void runIntegrityCheck(std::atomic<bool> &scanInProgress, std::mutex &oL_mutex, std::vector<std::wstring> &outputLines);
};