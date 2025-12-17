#include "Main.h"

wxIMPLEMENT_APP(App);

bool App::OnInit()
{
    if (!wxApp::OnInit()) {
        return false;
    }    

    // since we're storing our files containing message translations (called catalogs)
    // in l10n folder, search for them there
    wxFileTranslationsLoader::AddCatalogLookupPathPrefix("../l10n");

    // create the object for message translation and set it up for global use
    wxTranslations* const trans = new wxTranslations();
    wxTranslations::Set(trans);

    // initialize the catalog we'll be using
    if (!trans->AddCatalog("gui")) {
        wxLogError(_("Couldn't find/load the 'gui' message catalog (language translations)."));
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
    : wxFrame(nullptr, wxID_ANY, _("Main GUI Window"), wxDefaultPosition, wxSize(640, 480), wxDEFAULT_FRAME_STYLE)
{   
    // default gui's language is english
    // unused for now, up until we implement config file handling
    //currentLanguage = EN;

    // Create sizer and panel inside of it so we can add borders to our workspace
    wxBoxSizer* box = new wxBoxSizer(wxVERTICAL);
    mainPanel = new wxPanel(this);
    box->Add(mainPanel, 1, wxEXPAND | wxALL, 10);

    // Tell wxAuiManager to manage this window
    mgr.SetManagedWindow(mainPanel);

    // Create menu bar...
    wxMenuBar* mb = new wxMenuBar();

    // VIEW MENU
    wxMenu* viewMenu = new wxMenu();
    // Add actions to choose from the menu
    viewMenu->Append(ID_ADDP_SILLYTEXT, _("&Add a silly text panel"));
    Bind(wxEVT_MENU, &MainFrame::OnAddPanelSillytext, this, ID_ADDP_SILLYTEXT);
    viewMenu->Append(ID_ADDP_SCANINPROGRESS, _("&Add filesystem scan panel"));
    Bind(wxEVT_MENU, &MainFrame::OnAddPanelScanInProgress, this, ID_ADDP_SCANINPROGRESS);

    // PERSPECTIVES MENU
    wxMenu* perspectivesMenu = new wxMenu();
    perspectivesMenu->Append(ID_CREATE_PERSPECTIVE, _("&Create new"));
    Bind(wxEVT_MENU, &MainFrame::OnCreateNewPerspective, this, ID_CREATE_PERSPECTIVE);
    restorePerspectivesSubmenu = new wxMenu();
    perspectivesMenu->AppendSubMenu(restorePerspectivesSubmenu, _("&Restore perspective..."));
    restorePerspectivesSubmenu->Append(ID_FIRST_PERSPECTIVE, _("&Default"), _("Restore the default GUI look"));
    Bind(wxEVT_MENU, &MainFrame::OnRestorePerspective, this, ID_FIRST_PERSPECTIVE);
    restorePerspectivesSubmenu->AppendSeparator();
    
    // LANGUAGE MENU
    // unused for now, up until we implement config file handling
    /*wxMenu* languageMenu = new wxMenu();
    languageMenu->Append(ID_SET_GUI_LANGUAGE_ENGLISH, "&English");
    Bind(wxEVT_MENU, &MainFrame::OnSwitchLanguage, this, ID_SET_GUI_LANGUAGE_ENGLISH);
    languageMenu->Append(ID_SET_GUI_LANGUAGE_POLISH, "&Polski");
    Bind(wxEVT_MENU, &MainFrame::OnSwitchLanguage, this, ID_SET_GUI_LANGUAGE_POLISH);
    */
    mb->Append(viewMenu, _("&View"));
    mb->Append(perspectivesMenu, _("&Perspectives"));
    //mb->Append(languageMenu, _("&Language"));

    // Create panes
    mgr.AddPane(new wxTextCtrl(mainPanel, wxID_ANY, _("Im a silly text control")), wxAuiPaneInfo().Name("silly").Caption(_("Silly pane 1")).MinSize(200, 150).Bottom().Layer(0).Row(1).TopDockable(false).LeftDockable(false).RightDockable(false));
    //mgr.AddPane(new wxTextCtrl(mainPanel, wxID_ANY, "im a dumbass text control"), wxAuiPaneInfo().Name("test2").Caption("Dumbass pane 2").Top().Layer(0).Row(1));
    // Simplebook filesystem scan pane
    filesystemScanBook = new wxSimplebook(mainPanel);
    filesystemScanBook->AddPage(new LaunchScanPanel(filesystemScanBook), "", false, -1);
    filesystemScanBook->AddPage(new ScanInProgressPanel(filesystemScanBook), "", false -1);
    filesystemScanBook->SetSelection(0);
    Bind(wxEVT_BUTTON, &MainFrame::OnNextSystemscanBookPage, this, 3);
    mgr.AddPane(filesystemScanBook, wxAuiPaneInfo().Name("filesystemScan").Caption(_("Filesystem scan")).Bottom().Layer(0).Row(0).TopDockable(false).LeftDockable(false).RightDockable(false));
    //mgr.AddPane(new ScanInProgressPanel(mainPanel), wxAuiPaneInfo().Name("prog").Caption("Filesystem scan").Bottom().Layer(0).Row(0).TopDockable(false).LeftDockable(false).RightDockable(false));
    //mgr.AddPane(new LaunchScanPanel(mainPanel), wxAuiPaneInfo().Name("launch").Caption("Filesystem scan").Bottom().Layer(0).Row(0).TopDockable(false).LeftDockable(false).RightDockable(false));

    // Save their current placements as default perspective
    wxString perspectiveDefault = mgr.SavePerspective();
    perspectives[ID_FIRST_PERSPECTIVE] = perspectiveDefault;

    SetMenuBar(mb);
    this->SetSizer(box);
    mgr.Update();

    //Bind(wxEVT_SIZE, &MainFrame::OnResize, this);
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

void MainFrame::OnCreateNewPerspective(wxCommandEvent& event)
{
    
    int newPerspectivesId = ID_FIRST_PERSPECTIVE + (int)perspectives.size();
    perspectives[newPerspectivesId] = mgr.SavePerspective();
    
    restorePerspectivesSubmenu->Insert(2, newPerspectivesId, _("Perspective ") + to_string(newPerspectivesId - ID_FIRST_PERSPECTIVE));
    Bind(wxEVT_MENU, &MainFrame::OnRestorePerspective, this, newPerspectivesId);
    

    size_t howManyPerspectivesSaved = restorePerspectivesSubmenu->GetMenuItemCount();
    // more than 12 (default one + separator + 10 created ones) perspectives in the submenu list
    if (howManyPerspectivesSaved > 12) { 
        wxMenuItem* listItemToDelete = restorePerspectivesSubmenu->FindItemByPosition(howManyPerspectivesSaved - 1);
        restorePerspectivesSubmenu->Destroy(listItemToDelete); // delete the downmost list item
    }
}

void MainFrame::OnRestorePerspective(wxCommandEvent& event)
{
    wxString toBeRestoredPerspective = perspectives.find(event.GetId())->second;
    mgr.LoadPerspective(toBeRestoredPerspective);
}

//void MainFrame::OnSwitchLanguage(wxCommandEvent& event) 
//{
//    if (event.GetId() == ID_SET_GUI_LANGUAGE_POLISH && currentLanguage != PL) {
//       // in the future there's gonna be a beautiful write to config file here
//    }
//    if (event.GetId() == ID_SET_GUI_LANGUAGE_ENGLISH && currentLanguage != EN) {
//        wxMessageDialog* restartPlease = new wxMessageDialog(this, _("Please restart the program to switch to English"),
//            _("Restart please!"), wxOK | wxICON_WARNING, wxDefaultPosition);
//        restartPlease->ShowModal();
//    }
//    
//    
//}

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