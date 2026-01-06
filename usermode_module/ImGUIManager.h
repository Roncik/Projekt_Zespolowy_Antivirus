#pragma once

class ImGUIManager
{
private:
    static LPDIRECT3D9              g_pD3D;
    static LPDIRECT3DDEVICE9        g_pd3dDevice;
    static bool                     g_DeviceLost;
    static UINT                     g_ResizeWidth, g_ResizeHeight;
    static D3DPRESENT_PARAMETERS    g_d3dpp;

public:
    ~ImGUIManager()
    {
        CleanupDeviceD3D();
    }
    bool CreateDeviceD3D(HWND hWnd);
    void CleanupDeviceD3D();
    void ResetDevice();

    // Win32 message handler
   // You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
   // - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
   // - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
   // Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
    static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam); //callback for processing messages sent to window

    int example();
};