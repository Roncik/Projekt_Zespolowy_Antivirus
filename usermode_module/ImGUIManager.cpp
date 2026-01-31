#include "pch.h"
#include "ImGUIManager.h"
#include "TemporaryHelpers.h"
#include "SystemProcessDefender.h"
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>
#include <map>
//#include <chrono>

//static member definitions
 LPDIRECT3D9              ImGUIManager::g_pD3D = nullptr;
 LPDIRECT3DDEVICE9        ImGUIManager::g_pd3dDevice = nullptr;
 bool                     ImGUIManager::g_DeviceLost = false;
 UINT                     ImGUIManager::g_ResizeWidth = 0, ImGUIManager::g_ResizeHeight = 0;
 D3DPRESENT_PARAMETERS    ImGUIManager::g_d3dpp = {};

 // Forward declarations
 std::string convert_from_wstring(const std::wstring& wstr);
 std::ostream& operator<<(std::ostream& os, LogsManager::log_entry const& arg);
 std::string to_string(LogsManager::log_entry const& arg);

 // Used when user tries to close the program
 bool isTryingToExit = false;

// -----------------------------------------------------------------------
// ------------------------ D3DX9 + WIN32 --------------------------------
// -----------------------------------------------------------------------

bool ImGUIManager::CreateDeviceD3D(HWND hWnd)
{
    if ((ImGUIManager::g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    // Create the D3DDevice
    ZeroMemory(&ImGUIManager::g_d3dpp, sizeof(ImGUIManager::g_d3dpp));
    ImGUIManager::g_d3dpp.Windowed = TRUE;
    ImGUIManager::g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    ImGUIManager::g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
    ImGUIManager::g_d3dpp.EnableAutoDepthStencil = TRUE;
    ImGUIManager::g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    ImGUIManager::g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //ImGUIManager::g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (ImGUIManager::g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &ImGUIManager::g_d3dpp, &ImGUIManager::g_pd3dDevice) < 0)
        return false;

    return true;
}

void ImGUIManager::CleanupDeviceD3D()
{
    if (ImGUIManager::g_pd3dDevice)
    { 
        ImGUIManager::g_pd3dDevice->Release();
        ImGUIManager::g_pd3dDevice = nullptr;
    }
    if (ImGUIManager::g_pD3D)
    { 
        ImGUIManager::g_pD3D->Release();
        ImGUIManager::g_pD3D = nullptr;
    }
}

void ImGUIManager::ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = ImGUIManager::g_pd3dDevice->Reset(&ImGUIManager::g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT __stdcall ImGUIManager::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    else
    {
        switch (msg)
        {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED)
                return 0;
            g_ResizeWidth = (UINT)LOWORD(lParam); // Queue resize
            g_ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
                return 0;
            break;
        case WM_CLOSE:
            isTryingToExit = true;
            return 0;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
        }
        return ::DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}

// -----------------------------------------------------------------------
// -------------------------- GUI CORE -----------------------------------
// -----------------------------------------------------------------------

// Data shared between different functions of the main window
struct MainWindowData
{
    // Panels (child windows of the main window)
    bool showActiveProtectionConfigPanel = true;
    //bool showActiveProtectionConsoleOutputPanel = false; // its just the logger example despite the name
    bool showActiveProtectionOutputPanel = true;
};

// Used for scan logger module to GUI communication
// using TemporaryHelpers.cpp logging behaviour
static std::vector<std::wstring> outputLines;
static std::mutex oL_mutex;
// using SystemProcessDefender.cpp logging behaviour
std::vector<std::unique_ptr<LogsManager::log_entry>> logQueue{};        // Inter-thread queue, periodically joined into LogsManager::Logs and flushed
std::mutex lQ_mutex;

// Object needed to call its class' methods
static SystemProcessDefender spd{};

// Vector of threads running different antivirus functionalities (for now 10 slots for 10 functionalities)
std::vector<std::thread> workerThreads(10);
// Atomics signifying if worker threads are running
static std::atomic<bool> icInProgress(false);
static std::atomic<bool> sspfsmaInProgress(false);

// Run the main window
int ImGUIManager::RunUI()
{
    // Make process DPI aware and obtain main monitor scale
    ImGui_ImplWin32_EnableDpiAwareness();
    float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    // Create application window
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, this->WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"Antivirus Student Project", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Antivirus Student Project", WS_OVERLAPPEDWINDOW, 100, 100, (int)(800 * main_scale), (int)(600 * main_scale), nullptr, nullptr, wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Window data
    static MainWindowData mwData;

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;                   
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls    
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable window/panel docking
    io.ConfigFlags |= ImGuiWindowFlags_NoMove;                // Main panel non-movable    

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsLight();

    // Setup scaling
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(main_scale);        // Bake a fixed style scale. (until we have a solution for dynamic style scaling, changing this requires resetting Style + calling this again)
    style.FontScaleDpi = main_scale;        // Set initial font scale. (using io.ConfigDpiScaleFonts=true makes this unnecessary. We leave both here for documentation purpose)

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(ImGUIManager::g_pd3dDevice);

    // Load Fonts
    // - If no fonts are loaded, dear imgui will use the default font. You can also load multiple fonts and use ImGui::PushFont()/PopFont() to select them.
    // - AddFontFromFileTTF() will return the ImFont* so you can store it if you need to select the font among multiple.
    // - If the file cannot be loaded, the function will return a nullptr. Please handle those errors in your application (e.g. use an assertion, or display an error and quit).
    // - Use '#define IMGUI_ENABLE_FREETYPE' in your imconfig file to use Freetype for higher quality font rendering.
    // - Read 'docs/FONTS.md' for more instructions and details. If you like the default font but want it to scale better, consider using the 'ProggyVector' from the same author!
    // - Remember that in C/C++ if you want to include a backslash \ in a string literal you need to write a double backslash \\ !
    //style.FontSizeBase = 20.0f;
    //io.Fonts->AddFontDefault();
    //io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\segoeui.ttf");
    //io.Fonts->AddFontFromFileTTF("../../misc/fonts/DroidSans.ttf");
    //io.Fonts->AddFontFromFileTTF("../../misc/fonts/Roboto-Medium.ttf");
    //io.Fonts->AddFontFromFileTTF("../../misc/fonts/Cousine-Regular.ttf");
    //ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\ArialUni.ttf");
    //IM_ASSERT(font != nullptr);

    // Used when rendering
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);         

    // Used when user wants to skip waiting for threads to join when closing the program
    bool isForcingQuit = false;

    // Main loop
    bool done = false;
    while (!done)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // See the WndProc() function below for our to dispatch events to the Win32 backend.
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)        
                done = true;            
        }

        if (done)
            break;

        // Handle lost D3D9 device
        if (ImGUIManager::g_DeviceLost)
        {
            HRESULT hr = ImGUIManager::g_pd3dDevice->TestCooperativeLevel();
            if (hr == D3DERR_DEVICELOST)
            {
                ::Sleep(10);
                continue;
            }
            if (hr == D3DERR_DEVICENOTRESET)
                ResetDevice();
            ImGUIManager::g_DeviceLost = false;
        }

        // Handle window resize (we don't resize directly in the WM_SIZE handler)
        if (ImGUIManager::g_ResizeWidth != 0 && ImGUIManager::g_ResizeHeight != 0)
        {
            ImGUIManager::g_d3dpp.BackBufferWidth = ImGUIManager::g_ResizeWidth;
            ImGUIManager::g_d3dpp.BackBufferHeight = ImGUIManager::g_ResizeHeight;
            ImGUIManager::g_ResizeWidth = ImGUIManager::g_ResizeHeight = 0;
            ResetDevice();
        }

        // Start the Dear ImGui frame
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        ImGui::DockSpaceOverViewport();       

        if (isTryingToExit)
        {
            ImGui::OpenPopup("Quitting...");

            // Always center this window when appearing
            ImVec2 center = ImGui::GetMainViewport()->GetCenter();
            ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
            if (ImGui::BeginPopupModal("Quitting...", NULL, ImGuiWindowFlags_AlwaysAutoResize))
            {
                ImGui::Text("Waiting for all threads\nto finish their work...\n");
                ImGui::Separator();

                if (!(icInProgress || sspfsmaInProgress))
                    done = true;

                if (ImGui::Button("Go Back", ImVec2(120, 0)))
                {
                    isTryingToExit = false;
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine();
                if (ImGui::Button("Force Quit")) 
                {
                    isForcingQuit = true;
                    done = true;
                }                
                ImGui::EndPopup();
            }
        }
        
        // Show panels user chose as visible using menu options
        if (mwData.showActiveProtectionConfigPanel) 
        {
            ShowActiveProtectionConfigPanel(&mwData.showActiveProtectionConfigPanel); 
        }
        if (mwData.showActiveProtectionOutputPanel)
        {
            ShowActiveProtectionOutputPanel(&mwData.showActiveProtectionOutputPanel);
        }        

        // Create the always-visible main menu bar over the main viewport
        if (ImGui::BeginMainMenuBar())
        {            
            if (ImGui::BeginMenu("Panels"))
            {
                if (ImGui::MenuItem("Active protection config", NULL))                
                    mwData.showActiveProtectionConfigPanel = true;                                
                if (ImGui::MenuItem("Active protection console output", NULL))
                    mwData.showActiveProtectionOutputPanel = true;                                
                ImGui::EndMenu();
            }
            ImGui::EndMainMenuBar();
        }                     

        // Rendering
        ImGui::EndFrame();
        ImGUIManager::g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        ImGUIManager::g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        ImGUIManager::g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
        ImGUIManager::g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
        if (ImGUIManager::g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            ImGUIManager::g_pd3dDevice->EndScene();
        }
        HRESULT result = ImGUIManager::g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST)
            ImGUIManager::g_DeviceLost = true;
    }

    if (!isForcingQuit)
    {
        for (auto& thread : workerThreads)
        {
            if (thread.joinable())
                thread.join();            
        }
    }

    // Cleanup
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

// -----------------------------------------------------------------------
// ------------------------- PANELS (SUBWINDOWS) -------------------------
// -----------------------------------------------------------------------

// A panel to configure which scanning modules are to be actively running during
// program execution
void ImGUIManager::ShowActiveProtectionConfigPanel(bool* p_open)
{    
    ImGui::SetNextWindowSize(ImVec2(80, 160), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Active protection config", p_open))
    {        
        ImGui::SetNextItemWidth(65);
        ImGui::TextWrapped("Run modules");            

        // Outdated, for testing purposes only
        //ImGui::TextWrapped("Integrity check"); 
        //ImGui::SameLine(); 
        //if (ImGui::Button("Run##icRunButton")) 
        //{            
        //    if (!icInProgress)
        //    { 
        //        if (workerThreads.at(0).joinable()) // Empty thread handles (on freshly initialized vector) return false on .joinable(), so works for them also
        //            workerThreads.at(0).join();

        //        icInProgress = true;            
        //        workerThreads.at(0) = std::thread(moduleDeployer::runIntegrityCheck, std::ref(icInProgress), std::ref(oL_mutex), std::ref(outputLines));
        //    }          
        //}        
        ImGui::TextWrapped("ScanSystemProcessesForSuspiciousMemAllocations");        
        if (ImGui::Button("Run##sspfsmaRunButton"))
        {
            if (!sspfsmaInProgress)
            {
                if (workerThreads.at(1).joinable())
                    workerThreads.at(1).join();

                sspfsmaInProgress = true;
                workerThreads.at(1) = std::thread([](){   // lambda automatically has access to static variables (eg. logQueue), no need to pass by reference                   
                    spd.ScanSystemProcessesForSuspiciousMemAllocations(logQueue, lQ_mutex);
                    sspfsmaInProgress = false;
                });    // The aim is for threads to be joinable when scanning methods' are modified to perform scans in a loop. Loop stops when stop atomic bool is set to true. The main thread then waits for the threads to complete their current iterations to join, then terminates (eg on quitting the program by the user).
            }
        }
    }
    ImGui::End();
}

// Communicates with a worker runIntegrityCheck thread, checking a shared vector
// for new elements (new lines output by the scanning module) and updating the UI text field
// Also doing the same for ScanSystemProcessesForSuspiciousMemAllocations
void ImGUIManager::ShowActiveProtectionOutputPanel(bool* p_open)
{
    ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Active protection output", p_open))
    {
        ImGui::Text("Console output of running active protection modules.");

        //static ImGuiTextBuffer consoleOutput;
        //static int lines = 0;   // Outdated
        static ImGuiTextBuffer logTypeBuffer;
        static ImGuiTextBuffer logModulenameBuffer;
        static ImGuiTextBuffer logDateBuffer;
        static ImGuiTextBuffer logLocationBuffer;
        static ImGuiTextBuffer logFilenameBuffer;
        static ImGuiTextBuffer logActionBuffer;
        static ImGuiTextBuffer logStatusBuffer;
        static ImGuiTextBuffer logDescriptionBuffer;
        static ImGuiTextBuffer logExtrainfoBuffer;
        static bool logFileLoaded = false;

        if (ImGui::Button("Clear"))
        {
            //lines = 0;
            //consoleOutput.clear();
            logTypeBuffer.clear();
            logModulenameBuffer.clear();
            logDateBuffer.clear();
            logLocationBuffer.clear();
            logFilenameBuffer.clear();
            logActionBuffer.clear();
            logStatusBuffer.clear();
            logDescriptionBuffer.clear();
            logExtrainfoBuffer.clear();
            LogsManager::Logs.clear();
            logFileLoaded = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Load"))
        {
            if (!logFileLoaded) {
                if (!LogsManager::ReadLogsFromFile())
                {
                    //consoleOutput.appendf("[ERROR] Couldn't load the log file.\n");
                }
                else
                {
                    for (auto& log : LogsManager::Logs)
                    {
                        //consoleOutput.appendf(to_string(*log).c_str());
                        logTypeBuffer.appendf((log->Type + "\n").c_str());
                        logModulenameBuffer.appendf((log->Module_name + "\n").c_str());
                        logDateBuffer.appendf((log->Date + "\n").c_str());
                        logLocationBuffer.appendf((log->Location + "\n").c_str());
                        logFilenameBuffer.appendf((log->Filename + "\n").c_str());
                        logActionBuffer.appendf((log->Action + "\n").c_str());
                        logStatusBuffer.appendf((log->Status + "\n").c_str());
                        logDescriptionBuffer.appendf((log->Description + "\n").c_str());
                        logExtrainfoBuffer.appendf((log->Extra_info + "\n").c_str());
                    }
                    logFileLoaded = true;
                }
            }
        }
        
        // Getting the logs generated by scanning modules,
        // synchronized through simple mutexes
        static std::vector<std::unique_ptr<LogsManager::log_entry>> logBuffer{};
        std::unique_lock<std::mutex> lQ_ulock(lQ_mutex, std::defer_lock);
        lQ_ulock.lock();
            logBuffer.insert(logBuffer.end(), std::make_move_iterator(logQueue.begin()),
                                              std::make_move_iterator(logQueue.end()));
            logQueue.clear();
        lQ_ulock.unlock();

        // Log string split into fields, needed for processing
        static std::map<std::string, std::vector<std::string>> logFields
        {
            {"Type", std::vector<std::string>{ "\n" }},
            {"Module_name", std::vector<std::string>{ "\n" }},
            {"Date", std::vector<std::string>{ "\n" }},
            {"Location", std::vector<std::string>{ "\n" }},
            {"Filename", std::vector<std::string>{ "\n" }},
            {"Action", std::vector<std::string>{ "\n" }},
            {"Status", std::vector<std::string>{ "\n" }},
            {"Description", std::vector<std::string>{ "\n" }},
            {"Extra_info", std::vector<std::string>{ "\n" }}
        };

        // Writing to the log file        
        // And processing for future filtering queries
        for (auto& log : logBuffer)
        {
            if (!LogsManager::Log(*log))
            {
                //consoleOutput.appendf("[ERROR] Couldn't save scanner's logs into a file.\n");
            }                       
            //consoleOutput.appendf(to_string(*log).c_str());            
            logFields.at("Type").push_back(log->Type);
            logFields.at("Module_name").push_back(log->Module_name);
            logFields.at("Date").push_back(log->Date);
            logFields.at("Location").push_back(log->Location);
            logFields.at("Filename").push_back(log->Filename);
            logFields.at("Action").push_back(log->Action);
            logFields.at("Status").push_back(log->Status);
            logFields.at("Description").push_back(log->Description);
            logFields.at("Extra_info").push_back(log->Extra_info);
            logTypeBuffer.appendf((log->Type + "\n").c_str());
            logModulenameBuffer.appendf((log->Module_name + "\n").c_str());
            logDateBuffer.appendf((log->Date + "\n").c_str());
            logLocationBuffer.appendf((log->Location + "\n").c_str());
            logFilenameBuffer.appendf((log->Filename + "\n").c_str());
            logActionBuffer.appendf((log->Action + "\n").c_str());
            logStatusBuffer.appendf((log->Status + "\n").c_str());
            logDescriptionBuffer.appendf((log->Description + "\n").c_str());
            logExtrainfoBuffer.appendf((log->Extra_info + "\n").c_str());
            LogsManager::Logs.push_back(std::move(log));    
        }
        logBuffer.clear();                

        // Displaying the logs
        ImGui::BeginChild("LogsDisplayAreaChild", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders);
        {
            ImVec2 parentsSize = ImGui::GetContentRegionAvail();
            ImGui::BeginChild("TypeChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);            
                ImGui::TextUnformatted(logTypeBuffer.begin(), logTypeBuffer.end());           
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("ModulenameChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logModulenameBuffer.begin(), logModulenameBuffer.end());
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("DateChild", ImVec2(parentsSize[0]/9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logDateBuffer.begin(), logDateBuffer.end());
            ImGui::EndChild();          
            ImGui::SameLine();
            ImGui::BeginChild("LocationChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logLocationBuffer.begin(), logLocationBuffer.end());
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("FilenameChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logFilenameBuffer.begin(), logFilenameBuffer.end());
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("ActionChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logActionBuffer.begin(), logActionBuffer.end());
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("StatusChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logStatusBuffer.begin(), logStatusBuffer.end());
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("DescriptionChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logDescriptionBuffer.begin(), logDescriptionBuffer.end());
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::BeginChild("ExtrainfoChild", ImVec2(parentsSize[0] / 9.0f, 0.0f), ImGuiChildFlags_ResizeX, ImGuiWindowFlags_NoScrollbar);
                ImGui::TextUnformatted(logExtrainfoBuffer.begin(), logExtrainfoBuffer.end());
            ImGui::EndChild();
        }
        ImGui::EndChild();
        
    }
    ImGui::End();
}

// -----------------------------------------------------------------------
// ------------------------ HELPER FUNCTIONS -----------------------------
// -----------------------------------------------------------------------

// Helper to convert from wstring to string
std::string convert_from_wstring(const std::wstring& wstr)
{
    int num_chars = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string strTo;
    if (num_chars > 0)
    {
        strTo.resize(num_chars);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), wstr.length(), &strTo[0], num_chars, NULL, NULL);
    }
    return strTo;
}

// Helpers to convert log_entry structure into string
std::ostream& operator<<(std::ostream& os, LogsManager::log_entry const& arg)
{
    os << arg.Type << ";" << arg.Module_name << ";" << arg.Date << ";"
        << arg.Location << ";" << arg.Filename << ";" << arg.Action << ";"
        << arg.Status << ";" << arg.Description << ";" << arg.Extra_info << ";" << "\n";

    return os;
}
std::string to_string(LogsManager::log_entry const& arg)
{
    std::ostringstream ss;
    ss << arg;
    return std::move(ss).str(); // enable efficiencies in c++17
}