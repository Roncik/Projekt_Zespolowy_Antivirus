#pragma once
// For compilers that support precompilation, includes "wx/wx.h".
#include <wx/wxprec.h>

#ifndef WX_PRECOMP
    #include <wx/wx.h>
#endif

#include <wx/aui/aui.h>
#include "Panels.h"

#include "wx/intl.h"
#include "wx/translation.h"

#include <vector>
#include <string>
#include <map>

using namespace std;

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
    void OnCreateNewPerspective(wxCommandEvent& event);
    void OnRestorePerspective(wxCommandEvent& event);
    // unused for now, up until we implement config file handling
    //void OnSwitchLanguage(wxCommandEvent& event);
    void OnNextSystemscanBookPage(wxCommandEvent& event);
    //void OnResize(wxSizeEvent& event);

private:
    wxPanel* mainPanel;
    wxAuiManager mgr;    
    map<int, wxString> perspectives;
    wxMenu* restorePerspectivesSubmenu;
    //const wxTranslations* translation;

    wxSimplebook* filesystemScanBook;

    // unused for now, up until we implement config file handling
    /*enum uiLanguage{ PL, EN};
    uiLanguage currentLanguage;*/
};

enum {
    // IDs for adding panels to the workspace
    ID_ADDP_SILLYTEXT = 100,
    ID_ADDP_SCANINPROGRESS = 101,
    // ID for creating perspective
    ID_CREATE_PERSPECTIVE = 202,
    // Default perspective's ID used as a base point when creating new ones/restoring them
    ID_FIRST_PERSPECTIVE = 250,
    // IDs for choosing GUI language
    ID_SET_GUI_LANGUAGE_ENGLISH = 300,
    ID_SET_GUI_LANGUAGE_POLISH = 301
};