// Start of wxWidgets "Hello World" Program
#include <wx/stattext.h>
#include "Main.h"

// declared here cause class reference variables
class MyFrame : public wxFrame
{
public:
    MyFrame();
    LeftPanel* m_lp;
    RightPanel* m_rp;
    wxPanel* m_parent;
private:
    void OnHello(wxCommandEvent& event);
    void OnExit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
};
 
wxIMPLEMENT_APP(MyApp);
  
bool MyApp::OnInit()
{
    MyFrame *frame = new MyFrame();
    frame->Show(true);
    return true;
}
 
MyFrame::MyFrame()
    : wxFrame(nullptr, wxID_ANY, "BasicOkienko")
{
    wxMenu *menuFile = new wxMenu;
    menuFile->Append(ID_Hello, "&Hello...\tCtrl-H",
                     "Help string shown in status bar for this menu item");
    menuFile->AppendSeparator();
    menuFile->Append(wxID_EXIT);
 
    wxMenu *menuHelp = new wxMenu;
    menuHelp->Append(wxID_ABOUT);
 
    wxMenuBar *menuBar = new wxMenuBar;
    menuBar->Append(menuFile, "&File");
    menuBar->Append(menuHelp, "&Help");
 
    SetMenuBar( menuBar );
 
    CreateStatusBar();
    SetStatusText("Welcome to wxWidgets!");
 
    Bind(wxEVT_MENU, &MyFrame::OnHello, this, ID_Hello);
    Bind(wxEVT_MENU, &MyFrame::OnAbout, this, wxID_ABOUT);
    Bind(wxEVT_MENU, &MyFrame::OnExit, this, wxID_EXIT);

    m_parent = new wxPanel(this, wxID_ANY);

    wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL);

    m_lp = new LeftPanel(m_parent);
    m_rp = new RightPanel(m_parent);

    hbox->Add(m_lp, 1, wxEXPAND | wxALL, 5);
    hbox->Add(m_rp, 1, wxEXPAND | wxALL, 5);

    m_parent->SetSizer(hbox);
}
 
void MyFrame::OnExit(wxCommandEvent& event)
{
    Close(true);
}
 
void MyFrame::OnAbout(wxCommandEvent& event)
{
    wxMessageBox("This is a wxWidgets Hello World example",
                 "About Hello World", wxOK | wxICON_INFORMATION);
}
 
void MyFrame::OnHello(wxCommandEvent& event)
{
    wxLogMessage("Hello world from wxWidgets!");
}

LeftPanel::LeftPanel(wxPanel* parent)
    : wxPanel(parent, -1, wxPoint(-1, -1), wxSize(-1, -1), wxBORDER_SUNKEN)
{
    count = 0;
    m_parent = parent;
    m_plus = new wxButton(this, ID_PLUS, wxT("+"),
        wxPoint(10, 10));
    m_minus = new wxButton(this, ID_MINUS, wxT("-"),
        wxPoint(10, 60));
    Connect(ID_PLUS, wxEVT_COMMAND_BUTTON_CLICKED,
        wxCommandEventHandler(LeftPanel::OnPlus));
    Connect(ID_MINUS, wxEVT_COMMAND_BUTTON_CLICKED,
        wxCommandEventHandler(LeftPanel::OnMinus));

    m_text = new wxStaticText(this, -1, wxT("0"), wxPoint(10, 110));
}

void LeftPanel::OnPlus(wxCommandEvent& WXUNUSED(event))
{
    count++;
    m_text->SetLabel(wxString::Format(wxT("%d"), count));
}

void LeftPanel::OnMinus(wxCommandEvent& WXUNUSED(event))
{
    count--;
    m_text->SetLabel(wxString::Format(wxT("%d"), count));
}


RightPanel::RightPanel(wxPanel* parent)
    : wxPanel(parent, wxID_ANY, wxDefaultPosition,
        wxSize(270, 150), wxBORDER_SUNKEN)
{
    m_text = new wxStaticText(this, -1, wxT("0"), wxPoint(40, 60));
}