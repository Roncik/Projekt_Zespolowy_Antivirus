// PRECOMPILED HEADER FILE

#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <fstream>
#include <string>
#include <wincrypt.h>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <algorithm>
#include <tlhelp32.h>
#include <psapi.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")