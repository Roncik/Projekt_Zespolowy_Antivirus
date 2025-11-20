#pragma once
#include <wx/wx.h>
#include <wx/panel.h>
#include <wx/wxprec.h>
#include "Panels.h"

class MyApp : public wxApp
{
public:
    bool OnInit() override;
};

// menubar item
enum
{
    ID_Hello = 1
};

// declared here cause class reference variables
class MyFrame : public wxFrame
{
public:
    MyFrame();
    RightPanel* GetM_RP();
     
private:
    void OnHello(wxCommandEvent& event);
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);

    LeftPanel* m_lp;
    RightPanel* m_rp;
    wxPanel* m_parent;
};
