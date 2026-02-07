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
    if (ImGui::Begin("Active protection output", p_open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse))
    {               
        static bool logFileLoaded = false;
        bool newLogWasAdded = false;
        static bool logsNeedFiltering = false;

        // Clears the log display
        if (ImGui::Button("Clear"))
        {     
            LogsManager::Logs.clear();
            logFileLoaded = false;
            logsNeedFiltering = true;
        }
        // Loads logs from the logs file onto the display
        ImGui::SameLine();
        if (ImGui::Button("Load"))
        {
            if (!logFileLoaded) {
                if (!LogsManager::ReadLogsFromFile())
                    ;    // handle               
                else
                {
                    logFileLoaded = true;
                    newLogWasAdded = true;
                    logsNeedFiltering = true;
                }
            }
        }
        // Displays the searching/filtering logs interface
        ImGui::SameLine();
        ImGui::Text("Tools:");
        ImGui::SameLine();
        static bool searchPanelToggled = false;        
        if (ImGui::Button("Search"))
        {
            searchPanelToggled = !searchPanelToggled;
        }      
        ImGui::SameLine();
        static bool logDetailsViewerToggled = false;
        if (ImGui::Button("Log Details"))
        {
            logDetailsViewerToggled = !logDetailsViewerToggled;
        }
        // Displays a checkbox to turn on auto-scrolling to bottom when new entries are displayed
        ImGui::SameLine();
        float textWidth = ImGui::CalcTextSize("Auto-scroll").x;
        float checkboxWidth = ImGui::GetFrameHeight();
        ImGui::SetCursorPosX(ImGui::GetWindowContentRegionMax().x - textWidth - checkboxWidth - ImGui::GetStyle().ItemSpacing.x);
        ImGui::Text("Auto-scroll");
        ImGui::SameLine();
        static bool autoScrollEnabled = true;
        ImGui::Checkbox("##autoScrollCheckbox", &autoScrollEnabled);
        ImGui::Dummy(ImVec2(0.0f, 1.0f));   // Blank vertical space
        
        // Getting the logs generated by scanning modules, synchronized through simple mutexes
        static std::vector<std::unique_ptr<LogsManager::log_entry>> logBuffer{};
        std::unique_lock<std::mutex> lQ_ulock(lQ_mutex, std::defer_lock);
        lQ_ulock.lock();
        logBuffer.insert(logBuffer.end(), std::make_move_iterator(logQueue.begin()),
            std::make_move_iterator(logQueue.end()));
        logQueue.clear();
        lQ_ulock.unlock();
       
        // Writing to the log file                
        if (logBuffer.size() > 0)
        {
            for (auto& log : logBuffer)
            {
                if (!LogsManager::Log(*log))
                {
                    // handle
                }                                                            
                LogsManager::Logs.push_back(std::move(log));
            }
            logBuffer.clear();
            newLogWasAdded = true;
            logsNeedFiltering = true;
        }

        static ImGuiTextFilter filter;
        static std::vector<size_t> filteredIndices;        
        // Log fields (corresponding to columns) are displayed in the table in a specific order from left-to-right, defined in this vector
        const static std::vector<std::string> colsOrder{ "Date", "Type", "Module Name", "Location", "File Name", "Action", "Status", "Description", "Extra Info" };  // Need to adjust order in the for loop in the table creation below when changing this
        static std::vector<bool> colsHidden(9, false);  // Is column of index corresponding to colsOrder tagged as hidden by the user?
        // filterFlags says whether to include a particular field of the log_entry object
        // in the text pool being searched/filtered for keywords using the filtering tool
        // Each index corresponds to the same index in colsOrder
        static std::vector<bool> filterFlags(9, true);

        // Filter/search through logs tool's UI
        if (searchPanelToggled)
        {                       
            ImGui::Separator();                 
            ImGui::Text("Filter by: ");            
            for (int i = 0; i < colsOrder.size(); i++)
            {                
                ImGui::SameLine();

                float textWidth = ImGui::CalcTextSize(colsOrder[i].c_str()).x;
                float selectablesWidth = textWidth + (ImGui::GetStyle().FramePadding.x * 2.0f);                
                if (ImGui::Selectable(colsOrder[i].c_str(), filterFlags[i], 0, ImVec2(selectablesWidth, 0)))
                {
                    filterFlags[i] = !filterFlags[i];
                    logsNeedFiltering = true;
                }                
            }

            ImGui::Text("Search for:");
            ImGui::SameLine();
            if (filter.Draw("##TextFilterWidget", 180))
                logsNeedFiltering = true;
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
            ImGui::Text("Input: [str1 str2 ...] for AND, [str1, str2, ...] for OR");
            ImGui::PopStyleColor();
            ImGui::Separator();
        }

        // Need this here, before filtering (the vector's values below are from last frame, but it shouldn't make a difference to human eye)
        static std::vector<int> columnsTextColor(9, -1);   // -1 for hidden columns, default 
                     
        // Filtering the logs
        if (logsNeedFiltering)
        {
            filteredIndices.clear();
            for (int i = 0; i < LogsManager::Logs.size(); i++)
            {
                const auto& entry = LogsManager::Logs[i];
                bool isAMatch = false;
                
                for (int j = 0; j < 9; j++)
                {
                    if (columnsTextColor[j] != -1 && filterFlags[j] == true)    // columnsTextColor[j] == -1 when column is hidden, no need to filter then
                    {
                        std::string fieldsName = colsOrder[j];
                        if (fieldsName == "Type")
                        {
                            if (filter.PassFilter(entry->Type.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Module Name")
                        {
                            if (filter.PassFilter(entry->Module_name.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Date")
                        {
                            if (filter.PassFilter(entry->Date.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Location")
                        {
                            if (filter.PassFilter(entry->Location.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "File Name")
                        {
                            if (filter.PassFilter(entry->Filename.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Action")
                        {
                            if (filter.PassFilter(entry->Action.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Status")
                        {
                            if (filter.PassFilter(entry->Status.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Description")
                        {
                            if (filter.PassFilter(entry->Description.c_str()))
                                isAMatch = true;
                        }
                        if (fieldsName == "Extra Info")
                        {
                            if (filter.PassFilter(entry->Extra_info.c_str()))
                                isAMatch = true;
                        }                            
                    }                    
                }
                if (isAMatch)
                    filteredIndices.push_back(i);
            }
            logsNeedFiltering = false;
        }

        // Needed for the "details viewer" widget
        static std::string selectedCell = "";   // If user clicks a cell of the below table, its contents are displayed in a different widget
        static float logDetailsViewerHeight = 60.0f;
        const float minLogDetailsViewerHeight = 8.0f;
        
        // Displaying the logs        
        {
            ImGui::Separator();            

            const static ImGuiTableFlags tableFlags = ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Hideable;            
            static ImVec2 tableSize;
            if (logDetailsViewerToggled)
                tableSize = { 0, -logDetailsViewerHeight };
            else
                tableSize = { 0,0 };

            ImGui::BeginTable("LogsTable", 9, tableFlags, tableSize);
            {
                // Ensures headers stay in place while scrolling
                ImGui::TableSetupScrollFreeze(0, 1);                
                
                // Column titles (headers)
                for (auto& colTitle : colsOrder)
                    ImGui::TableSetupColumn(colTitle.c_str());
                ImGui::TableHeadersRow();
                                
                int visibleColumnsCount = 0;    // They are gonna be 1 for def text color, 2 for darker, -1 for hidden column
                for (int column = 0; column < 9; column++)
                {
                     ImGuiTableColumnFlags colFlags = ImGui::TableGetColumnFlags(column);
                     if (colFlags & ImGuiTableColumnFlags_IsEnabled)
                     {
                         columnsTextColor[column] = (visibleColumnsCount % 2) + 1;
                         visibleColumnsCount++;
                     }
                     else
                         columnsTextColor[column] = -1; // Hidden column
                }

                // Clipper makes it so only those LogsManager::Logs elements that the column scroll
                // position indicates should be displayed are rendered
                // So no wasting resources on looping through whole Logs vector
                ImGuiListClipper clipper;
                clipper.Begin(filteredIndices.size());
                while (clipper.Step())
                {
                    for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
                    {
                        ImGui::TableNextRow();
                      
                        size_t idx = filteredIndices[i];
                        const auto& log = LogsManager::Logs[idx];                                            
                        ImGUIManager::SetupLogsTableColumn(0, columnsTextColor[0], i, log->Date, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(1, columnsTextColor[1], i, log->Type, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(2, columnsTextColor[2], i, log->Module_name, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(3, columnsTextColor[3], i, log->Location, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(4, columnsTextColor[4], i, log->Filename, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(5, columnsTextColor[5], i, log->Action, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(6, columnsTextColor[6], i, log->Status, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(7, columnsTextColor[7], i, log->Description, selectedCell);
                        ImGUIManager::SetupLogsTableColumn(8, columnsTextColor[8], i, log->Extra_info, selectedCell);
                    }
                }
                if (autoScrollEnabled)
                {
                    if (newLogWasAdded)
                        ImGui::SetScrollHereY(1.0f);    // Auto-scroll to the bottom when new logs being added
                }
            }
            ImGui::EndTable();
        }

        // Selected log field display (strings can be too long and get their ends cut off in the table, this is here to help)
        if (logDetailsViewerToggled)
        {
            ImGui::Separator();

            // Dynamically resizeable height of the panel (splitter)
            ImGui::Button("##Splitter", ImVec2(-1, 8.0f));
            if (ImGui::IsItemActive())
            {
                logDetailsViewerHeight -= ImGui::GetIO().MouseDelta.y;
                if (logDetailsViewerHeight < minLogDetailsViewerHeight)
                    logDetailsViewerHeight = minLogDetailsViewerHeight;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
                        
            ImGui::BeginChild("Details viewer", ImVec2(0, 0));
            {
                ImGui::Text("[CONTENTS]:");
                ImGui::SameLine();
                if (selectedCell.empty())
                    ImGui::TextDisabled("Click a cell to see its full contents...");
                else
                    ImGui::TextWrapped("%s", selectedCell.c_str());
            }
            ImGui::EndChild();
        }        
    }
    ImGui::End();
}

// -----------------------------------------------------------------------
// ----------------------- HELPER METHODS --------------------------------
// -----------------------------------------------------------------------

void ImGUIManager::SetupLogsTableColumn(int colIndex, int colTextColor, int i, std::string& cellContents, std::string& selectedCell)
{
        ImGui::TableSetColumnIndex(colIndex);
        if (ImGui::Selectable(("##cell_" + std::to_string(colIndex) + std::to_string(i)).c_str(), false))
            selectedCell = cellContents;
        ImGui::SameLine();
        if (colTextColor == 2)  // Different color
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(150 / 255.0f, 150 / 255.0f, 155 / 255.0f, 1.0f));
        ImGui::TextUnformatted(cellContents.c_str());
        if (colTextColor == 2)
            ImGui::PopStyleColor();    
}