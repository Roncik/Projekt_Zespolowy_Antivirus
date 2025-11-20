#include "Panels.h"
#include "Main.h"


LeftPanel::LeftPanel(wxPanel* parent)
    : wxPanel(parent, -1, wxPoint(0, 0), wxDefaultSize, wxBORDER_SUNKEN)
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

void LeftPanel::OnPlus(wxCommandEvent& event)
{
    count++;
    int x = count + 1;
    m_text->SetLabel(wxString::Format(wxT("%d"), MyBackendClass::TestFunction(count, x)));

    MyFrame* frame = (MyFrame*)m_parent->GetParent();
    frame->GetM_RP()->GetM_Text()->SetLabel(wxString::Format(wxT("%d"), count));
    
}

void LeftPanel::OnMinus(wxCommandEvent& WXUNUSED(event))
{
    count--;
    m_text->SetLabel(wxString::Format(wxT("%d"), count));

    MyFrame* frame = (MyFrame*)m_parent->GetParent();
    frame->GetM_RP()->GetM_Text()->SetLabel(wxString::Format(wxT("%d"), count));
}

RightPanel::RightPanel(wxPanel* parent)
    : wxPanel(parent, wxID_ANY, wxDefaultPosition,
        wxDefaultSize, wxBORDER_SUNKEN)
{

    m_text = new wxStaticText(this, -1, wxT("0"), wxPoint(40, 60));
    wxButton* butt = new wxButton(this, wxID_EXIT); // default windows ids demonstration
}

wxStaticText* RightPanel::GetM_Text() {
    return m_text;
}

BottomPanel::BottomPanel(wxPanel* parent)
    : wxPanel(parent) 
{
    wxGridSizer* gs = new wxGridSizer(1, 2, 5, 5);

    wxButton* btn1 = new wxButton(this, 1, wxT("Click"));
    wxButton* btn2 = new wxButton(this, 2, wxT("for errors"));

    Bind(wxEVT_COMMAND_BUTTON_CLICKED, &BottomPanel::ShowMessageError, this, 1);
    Bind(wxEVT_COMMAND_BUTTON_CLICKED, &BottomPanel::ShowMessageError, this, 2);

    gs->Add(btn1, 1, wxEXPAND);
    gs->Add(btn2, 1, wxEXPAND);
    SetSizer(gs);
}

void BottomPanel::ShowMessageError(wxCommandEvent& event) {
    wxMessageDialog* dial = new wxMessageDialog(nullptr, wxT("Im an error :3"), wxT("Error"), wxOK | wxICON_ERROR);
    dial->ShowModal();
}