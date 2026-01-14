#include "pch.h"
#include "ImGUIManager.h"
#include "TemporaryHelpers.h"
#include <mutex>
#include <thread>
#include <vector>
//#include <chrono>

//static member definitions
 LPDIRECT3D9              ImGUIManager::g_pD3D = nullptr;
 LPDIRECT3DDEVICE9        ImGUIManager::g_pd3dDevice = nullptr;
 bool                     ImGUIManager::g_DeviceLost = false;
 UINT                     ImGUIManager::g_ResizeWidth = 0, ImGUIManager::g_ResizeHeight = 0;
 D3DPRESENT_PARAMETERS    ImGUIManager::g_d3dpp = {};

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
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
        }
        return ::DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}

// Data shared between different functions of the main window
struct MainWindowData
{
    // Panels (child windows of the main window)
    bool showActiveProtectionConfigPanel = false;
    //bool showActiveProtectionConsoleOutputPanel = false; // its just the logger example despite the name
    bool showActiveProtectionOutputPanel = false;
};

// Needed for antivirus scan module and GUI integration
static std::vector<std::wstring> outputLines;
static std::mutex oL_mutex;

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
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
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

    // Our state
    bool show_demo_window = true;
    bool show_another_window = false;
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    // GUI Navigation variables
    uint8_t main_nav_bar = 0;

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
        //ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport(), ImGuiDockNodeFlags_PassthruCentralNode);    // Transparent dockspace

        if (mwData.showActiveProtectionConfigPanel) 
        {
            ShowActiveProtectionConfigPanel(&mwData.showActiveProtectionConfigPanel); 
        }
        if (mwData.showActiveProtectionOutputPanel)
        {
            ShowActiveProtectionOutputPanel(&mwData.showActiveProtectionOutputPanel);
        }
        /*  if (mwData.showActiveProtectionConsoleOutputPanel)
        {
            ShowExampleAppLog(&mwData.showActiveProtectionConsoleOutputPanel);
        }*/

        //ImGui::SetNextWindowPos({ 0,0 }, ImGuiCond_Once);
        //ImGui::SetNextWindowSize({ (1280 * main_scale), (800 * main_scale) });
        //ImGui::SetNextWindowBgAlpha(1.0f);

        // flags for imgui begin main window
        //ImGuiWindowFlags_NoResize |
        //    ImGuiWindowFlags_NoSavedSettings |
        //    ImGuiWindowFlags_NoCollapse |
        //    ImGuiWindowFlags_NoScrollbar |
        //    ImGuiWindowFlags_NoTitleBar |
        //    ImGuiWindowFlags_MenuBar

        // Create the always-visible main menu bar over the main viewport
        if (ImGui::BeginMainMenuBar())
        {
            if (ImGui::BeginMenu("View"))
            {             
                ImGui::EndMenu();
            }
            if (ImGui::BeginMenu("Panels"))
            {
                if (ImGui::MenuItem("Active protection config", NULL))                
                    mwData.showActiveProtectionConfigPanel = true;                
                /*if (ImGui::MenuItem("Active protection console output", NULL))                
                    mwData.showActiveProtectionConsoleOutputPanel = true;*/
                if (ImGui::MenuItem("Active protection console output", NULL))
                    mwData.showActiveProtectionOutputPanel = true;
                
                // example on how to program a menu
                //if (ImGui::MenuItem("Undo", "Ctrl+Z")) {}
                //if (ImGui::MenuItem("Redo", "Ctrl+Y", false, false)) {} // Disabled item
                //ImGui::Separator();
                //if (ImGui::MenuItem("Cut", "Ctrl+X")) {}
                //if (ImGui::MenuItem("Copy", "Ctrl+C")) {}
                //if (ImGui::MenuItem("Paste", "Ctrl+V")) {}
                ImGui::EndMenu();
            }
            ImGui::EndMainMenuBar();
        }

        // 1. Show the big demo window (Most of the sample code is in ImGui::ShowDemoWindow()! You can browse its code to learn more about Dear ImGui!).
          /* if (show_demo_window)
                ImGui::ShowDemoWindow(&show_demo_window);*/

        // 2. Show a simple window that we create ourselves. We use a Begin/End pair to create a named window.
        {//
        //    static float f = 0.0f;
        //    static int counter = 0;

        //    ImGui::Begin("Hello, world!");                          // Create a window called "Hello, world!" and append into it.

        //    ImGui::Text("This is some useful text.");               // Display some text (you can use a format strings too)
        //    ImGui::Checkbox("Demo Window", &show_demo_window);      // Edit bools storing our window open/close state
        //    ImGui::Checkbox("Another Window", &show_another_window);

        //    ImGui::SliderFloat("float", &f, 0.0f, 1.0f);            // Edit 1 float using a slider from 0.0f to 1.0f
        //    ImGui::ColorEdit3("clear color", (float*)&clear_color); // Edit 3 floats representing a color

        //    if (ImGui::Button("Button"))                            // Buttons return true when clicked (most widgets return true when edited/activated)
        //        counter++;
        //    ImGui::SameLine();
        //    ImGui::Text("counter = %d", counter);

        //    ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
        //    ImGui::End();
        }

        // 3. Show another simple window.        
        {//if (show_another_window)
        //{
        //    ImGui::Begin("Another Window", &show_another_window);   // Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
        //    ImGui::Text("Hello from another window!");
        //    if (ImGui::Button("Close Me"))
        //        show_another_window = false;
        //    ImGui::End();
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

    // Cleanup
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

void ImGUIManager::ShowActiveProtectionConfigPanel(bool* p_open) 
{    
    ImGui::SetNextWindowSize(ImVec2(80, 160), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Active protection config", p_open))
    {        
        ImGui::SetNextItemWidth(65);
        ImGui::TextWrapped("Run modules");
                
        static bool scanRunning = false;    // Initialize only at first pass of this line
        static std::mutex sR_mutex;                    

        ImGui::TextWrapped("Integrity check"); 
        ImGui::SameLine(); 
        if (ImGui::Button("Run")) 
        {
            std::unique_lock<std::mutex> sR_lock(sR_mutex);
            if (!scanRunning)
            {                
                sR_lock.unlock();
                std::thread(moduleDeployer::runIntegrityCheck, &scanRunning, std::ref(sR_mutex), std::ref(oL_mutex), std::ref(outputLines)).detach();
            }          
        }        
    }
    ImGui::End();
}

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

// Communicates with a worker runIntegrityCheck thread, checking a shared vector
// for new elements (new lines output by the scanning module) and updating the UI text field
void ImGUIManager::ShowActiveProtectionOutputPanel(bool* p_open)
{
    ImGui::SetNextWindowSize(ImVec2(300, 300), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Active protection output", p_open))
    {
        ImGui::Text("Console output of running active protection modules.");

        static ImGuiTextBuffer consoleOutput;  
        static int lines = 0;

        if (ImGui::Button("Clear")) { consoleOutput.clear(); lines = 0; }               
        ImGui::SameLine();
        if (ImGui::Button("Add text")) { consoleOutput.appendf("%i The quick brown fox jumps over the lazy dog\n", ++lines); }

        std::unique_lock<std::mutex> oL_lock(oL_mutex);
            if (outputLines.size() > 0)
            {
                for (std::wstring line : outputLines)
                    consoleOutput.appendf(convert_from_wstring(line).c_str());
                outputLines.clear();
            }
        oL_lock.unlock();

        ImGui::BeginChild("Output field");                       
        ImGui::TextUnformatted(consoleOutput.begin(), consoleOutput.end());        
        ImGui::EndChild();
    }
    ImGui::End();
}