#include "Main.h"

wxIMPLEMENT_APP(App);

bool App::OnInit()
{
    if (!wxApp::OnInit()) {
        return false;
    }

    MainFrame *frame = new MainFrame();
    frame->Show(true);

    return true;
}

/*
        const int sel = oldBook->GetSelection();
            m_bookCtrl->SetSelection(sel);
            wxSimplebook,
                     (m_panel, wxID_ANY, wxDefaultPosition, wxDefaultSize, flags));


*/

MainFrame::MainFrame()
    : wxFrame(nullptr, wxID_ANY, "Main GUI Window", wxDefaultPosition, wxSize(640, 480), wxDEFAULT_FRAME_STYLE)
{   
    // Create sizer and panel inside of it so we can add borders to our workspace
    wxBoxSizer* box = new wxBoxSizer(wxVERTICAL);
    mainPanel = new wxPanel(this);
    box->Add(mainPanel, 1, wxEXPAND | wxALL, 10);

    // Tell wxAuiManager to manage this window
    mgr.SetManagedWindow(mainPanel);

    // Create menu
    wxMenuBar* mb = new wxMenuBar();

    wxMenu* viewMenu = new wxMenu();
    viewMenu->Append(ID_ADDP_SILLYTEXT, "&Add a silly text panel");
    Bind(wxEVT_MENU, &MainFrame::OnAddPanelSillytext, this, ID_ADDP_SILLYTEXT);
    viewMenu->Append(ID_ADDP_SCANINPROGRESS, "&Add filesystem scan panel");
    Bind(wxEVT_MENU, &MainFrame::OnAddPanelScanInProgress, this, ID_ADDP_SCANINPROGRESS);

    wxMenu* perspectivesMenu = new wxMenu();
    // Add actions to choose from the menu
    perspectivesMenu->Append(ID_DEF_PERSPECTIVE, "&Restore default", "Restore the default GUI look");
    Bind(wxEVT_MENU, &MainFrame::OnRestorePerspective, this, ID_DEF_PERSPECTIVE);
    
    mb->Append(viewMenu, "&View");
    mb->Append(perspectivesMenu, "&Perspectives");

    // Create panes
    mgr.AddPane(new wxTextCtrl(mainPanel, wxID_ANY, "Im a silly text control"), wxAuiPaneInfo().Name("silly").Caption("Silly pane 1").MinSize(200, 150).Bottom().Layer(0).Row(1).TopDockable(false).LeftDockable(false).RightDockable(false));
    //mgr.AddPane(new wxTextCtrl(mainPanel, wxID_ANY, "im a dumbass text control"), wxAuiPaneInfo().Name("test2").Caption("Dumbass pane 2").Top().Layer(0).Row(1));
    // Simplebook filesystem scan pane
    filesystemScanBook = new wxSimplebook(mainPanel);
    filesystemScanBook->AddPage(new LaunchScanPanel(filesystemScanBook), "", false, -1);
    filesystemScanBook->AddPage(new ScanInProgressPanel(filesystemScanBook), "", false -1);
    filesystemScanBook->SetSelection(0);
    Bind(wxEVT_BUTTON, &MainFrame::OnNextSystemscanBookPage, this, 3);
    mgr.AddPane(filesystemScanBook, wxAuiPaneInfo().Name("filesystemScan").Caption("Filesystem scan").Bottom().Layer(0).Row(0).TopDockable(false).LeftDockable(false).RightDockable(false));
    //mgr.AddPane(new ScanInProgressPanel(mainPanel), wxAuiPaneInfo().Name("prog").Caption("Filesystem scan").Bottom().Layer(0).Row(0).TopDockable(false).LeftDockable(false).RightDockable(false));
    //mgr.AddPane(new LaunchScanPanel(mainPanel), wxAuiPaneInfo().Name("launch").Caption("Filesystem scan").Bottom().Layer(0).Row(0).TopDockable(false).LeftDockable(false).RightDockable(false));

    // Save their current placements as default perspective
    wxString perspectiveDefault = mgr.SavePerspective();
    perspectives.Add(perspectiveDefault);    

    SetMenuBar(mb);
    this->SetSizer(box);
    mgr.Update();

    //Bind(wxEVT_SIZE, &MainFrame::OnResize, this);
}

void MainFrame::OnRestorePerspective(wxCommandEvent& event)
{
    mgr.LoadPerspective(perspectives.Item(event.GetId() - ID_FIRST_PERSPECTIVE - 1));
}

void MainFrame::OnAddPanelSillytext(wxCommandEvent& event)
{
    wxAuiPaneInfo& foundPanel = mgr.GetPane("silly");
    // In case the panel is hidden; show it
    if (!(foundPanel.IsShown())) {
        foundPanel.Show();
        mgr.Update();
    }
}

void MainFrame::OnAddPanelScanInProgress(wxCommandEvent& event)
{
    wxAuiPaneInfo& foundPanel = mgr.GetPane("filesystemScan");
    // In case the panel is hidden; show it
    if (!(foundPanel.IsShown())) {
        foundPanel.Show();
        mgr.Update();
    }
}

void MainFrame::OnNextSystemscanBookPage(wxCommandEvent& event)
{
    filesystemScanBook->SetSelection((filesystemScanBook->GetSelection() + 1) % 2);
}


//void MainFrame::OnResize(wxSizeEvent& event)
//{
//    mgr1.Update();
//    mgr2.Update();
//    event.Skip();
//}