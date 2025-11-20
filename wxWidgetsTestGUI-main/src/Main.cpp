// Start of wxWidgets "Hello World" Program
#include <wx/stattext.h>
#include <wx/stdpaths.h>
#include "Main.h"

wxIMPLEMENT_APP(MyApp);
  
bool MyApp::OnInit()
{
    MyFrame *frame = new MyFrame();
    frame->Show(true);
    return true;
}
 
MyFrame::MyFrame()
    : wxFrame(nullptr, wxID_ANY, "BasicOkienko", wxPoint(0, 0), wxSize(500, 350), wxDEFAULT_FRAME_STYLE, wxT("MeinFreim"))
{
    wxString iconsPath = wxStandardPaths::Get().GetDataDir();
    iconsPath.wxString::Replace("\\bin", "\\imgs\\ikonka.xpm"); // assuming our icon file is in BasicOkienko/imgs
    wxImage::AddHandler(new wxXPMHandler);
    SetIcon(wxIcon(iconsPath, wxBITMAP_TYPE_XPM));    // wxT is for ansi strings wrapping, _() for Unicode

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

    // PANELS SECTION
    m_parent = new wxPanel(this, wxID_ANY);
    m_lp = new LeftPanel(m_parent);
    m_rp = new RightPanel(m_parent);
    wxPanel* bp = new BottomPanel(m_parent);

    wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);
    wxBoxSizer* hbox1 = new wxBoxSizer(wxHORIZONTAL);
    wxBoxSizer* hbox2 = new wxBoxSizer(wxHORIZONTAL);
    //hbox1->Add(m_parent, 1, wxEXPAND | wxALL, 5);
    hbox1->Add(m_lp, 1, wxEXPAND | wxALL, 5);
    hbox1->Add(m_rp, 2, wxEXPAND | wxALL, 5);
    vbox->Add(hbox1, 1, wxEXPAND | wxBOTTOM, 5);
    hbox2->Add(bp, 1, wxEXPAND | wxALL, 5);
    vbox->Add(hbox2, 1, wxEXPAND | wxBottom, 5);

    m_parent->SetSizer(vbox);
    Center();
}
 
// some compilers ramble bout unused params, WXUNUSED helps
void MyFrame::OnExit(wxCommandEvent& WXUNUSED(event))
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

RightPanel* MyFrame::GetM_RP() {
    return m_rp;
}
