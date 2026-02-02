// PRECOMPILED HEADER FILE
#define WIN32_LEAN_AND_MEAN

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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <map>
#include <cctype>
#include <stdexcept>
#include <winhttp.h>
#include <d3d9.h>
#include <d3dx9.h>
#include <tchar.h>
#include <winioctl.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

// Library for json - https://github.com/nlohmann/json
#include "nlohmann/json.hpp"

// ImGUI - https://github.com/ocornut/imgui
#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"



