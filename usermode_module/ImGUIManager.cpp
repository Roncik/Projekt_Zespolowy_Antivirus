#include "pch.h"
#include "ImGUIManager.h"
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
                    // handle
                }
                else
                {
                    for (auto& log : LogsManager::Logs)
                    {                        
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
        bool newLogWasAdded = false;
        if (logBuffer.size() > 0)
        {
            for (auto& log : logBuffer)
            {
                if (!LogsManager::Log(*log))
                {
                    // handle
                }                            
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
            newLogWasAdded = true;
        }

        // Needed for the "details viewer" widget
        static std::string selectedCell = "";   // If user clicks a cell of the below table, its contents are displayed in a different widget
        static float detailsViewerHeight = 60.0f;
        
        // Displaying the logs        
        {
            ImGui::Separator();
            //ImGui::PushStyleColor(ImGuiCol_TableRowBg, ImVec4());

            const static ImGuiTableFlags tableFlags = ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Hideable;

            ImGui::BeginTable("LogsTable", 9, tableFlags, ImVec2(0, -detailsViewerHeight));
            {
                // Ensures headers stay in place while scrolling
                ImGui::TableSetupScrollFreeze(0, 1);

                // Column titles (headers)
                const static std::vector<std::string> colsOrder{ "Date", "Type", "Module Name", "Location", "File Name", "Action", "Status", "Description", "Extra Info" };  // Need to adjust order in the for loop below when changing this
                for (auto& colTitle : colsOrder)
                    ImGui::TableSetupColumn(colTitle.c_str());
                ImGui::TableHeadersRow();

                // Clipper makes it so only those LogsManager::Logs elements that the column scroll
                // position indicates should be displayed are rendered
                // So no wasting resources on looping through whole Logs vector
                ImGuiListClipper clipper;
                clipper.Begin(LogsManager::Logs.size());
                while (clipper.Step())
                {
                    for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++)
                    {
                        ImGui::TableNextRow();

                        // Set even columns' color to a different one
                        /*for (int idx = 0; idx < colsOrder.size(); idx += 2)
                            ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, ImGui::GetColorU32(ImGuiCol_TableRowBgAlt), idx);*/

                        const auto& log = LogsManager::Logs[row];
                        ImGui::TableSetColumnIndex(0);
                            if (ImGui::Selectable(("##cell_0" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Date;
                            ImGui::SameLine();
                            ImGui::TextUnformatted(log->Date.c_str());
                        ImGui::TableSetColumnIndex(1);
                            if (ImGui::Selectable(("##cell_1" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Type;
                            ImGui::SameLine();
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(150 / 255.0f, 150 / 255.0f, 155 / 255.0f, 1.0f));
                            ImGui::TextUnformatted(log->Type.c_str());
                            ImGui::PopStyleColor();
                        ImGui::TableSetColumnIndex(2);       
                            if (ImGui::Selectable(("##cell_2" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Module_name;
                            ImGui::SameLine();
                            ImGui::TextUnformatted(log->Module_name.c_str());                        
                        ImGui::TableSetColumnIndex(3);
                            if (ImGui::Selectable(("##cell_3" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Location;
                            ImGui::SameLine();
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(150 / 255.0f, 150 / 255.0f, 155 / 255.0f, 1.0f));
                            ImGui::TextUnformatted(log->Location.c_str());
                            ImGui::PopStyleColor();
                        ImGui::TableSetColumnIndex(4);
                            if (ImGui::Selectable(("##cell_4" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Filename;
                            ImGui::SameLine();
                            ImGui::TextUnformatted(log->Filename.c_str());
                        ImGui::TableSetColumnIndex(5);
                            if (ImGui::Selectable(("##cell_5" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Action;
                            ImGui::SameLine();
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(150 / 255.0f, 150 / 255.0f, 155 / 255.0f, 1.0f));
                            ImGui::TextUnformatted(log->Action.c_str());
                            ImGui::PopStyleColor();
                        ImGui::TableSetColumnIndex(6);
                            if (ImGui::Selectable(("##cell_6" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Status;
                            ImGui::SameLine();
                            ImGui::TextUnformatted(log->Status.c_str());
                        ImGui::TableSetColumnIndex(7);
                            if (ImGui::Selectable(("##cell_7" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Description;
                            ImGui::SameLine();
                            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(150 / 255.0f, 150 / 255.0f, 155 / 255.0f, 1.0f));
                            ImGui::TextUnformatted(log->Description.c_str());
                            ImGui::PopStyleColor();
                        ImGui::TableSetColumnIndex(8);
                            if (ImGui::Selectable(("##cell_8" + std::to_string(row)).c_str(), false))
                                selectedCell = log->Extra_info;
                            ImGui::SameLine();
                            ImGui::TextUnformatted(log->Extra_info.c_str());
                    }
                }
                if (newLogWasAdded)
                    ImGui::SetScrollHereY(1.0f);    // Auto-scroll to the bottom when new logs being added
            }
            ImGui::EndTable();
        }

        // Selected log field display (strings can be too long and get their ends cut off in the table, this is here to help)
        ImGui::Separator();
        ImGui::Text("Expands to:");
        ImGui::BeginChild("Details viewer", ImVec2(0, 0));
        {
            if (selectedCell.empty())
                ImGui::TextDisabled("Click a cell to see full content...");
            else
                ImGui::TextWrapped("%s", selectedCell.c_str());
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