#pragma once
// For compilers that support precompilation, includes "wx/wx.h".
#include <wx/wxprec.h>

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <wx/aui/aui.h>
#include "Panels.h"

// Top-level App class
class App : public wxApp
{
public:
    virtual bool OnInit() override;
};

// Main start-up window of the GUI
class MainFrame : public wxFrame
{
public:
    MainFrame();

private:
    void OnAddPanelSillytext(wxCommandEvent& event);
    void OnAddPanelScanInProgress(wxCommandEvent& event);
    void OnRestorePerspective(wxCommandEvent& event);
    void OnNextSystemscanBookPage(wxCommandEvent& event);
    //void OnResize(wxSizeEvent& event);

private:
    wxPanel* mainPanel;
    wxAuiManager mgr;
    wxArrayString perspectives;

    wxSimplebook* filesystemScanBook;
};

enum {
    // IDs for adding panels to the workspace
    ID_ADDP_SILLYTEXT = 100,
    ID_ADDP_SCANINPROGRESS = 101,
    // Perspective IDs used as base points when creating new ones
    ID_FIRST_PERSPECTIVE = 200,
    ID_DEF_PERSPECTIVE = 201
};