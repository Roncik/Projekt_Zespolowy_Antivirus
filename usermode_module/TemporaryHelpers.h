#pragma once

class moduleDeployer
{
public:


    static void runIntegrityCheck(bool* scanRunning, std::mutex &sR_mutex, std::mutex &oL_mutex, std::vector<std::wstring> &outputLines);
};