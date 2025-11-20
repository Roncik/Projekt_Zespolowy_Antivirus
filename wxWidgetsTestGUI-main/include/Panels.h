#pragma once
#include "wx/wx.h"
#include "Backend.h"

class LeftPanel : public wxPanel
{
public:
    LeftPanel(wxPanel* parent);
    void OnPlus(wxCommandEvent& event);
    void OnMinus(wxCommandEvent& event);
private:
    wxButton* m_plus;
    wxButton* m_minus;
    wxPanel* m_parent;
    int count;
    wxStaticText* m_text;

};

class RightPanel : public wxPanel
{
public:
    RightPanel(wxPanel* parent);
    void OnSetText(wxCommandEvent& event);
    wxStaticText* GetM_Text();
private:
    wxStaticText* m_text;
};

class BottomPanel : public wxPanel {
public:
    BottomPanel(wxPanel* parent);

private:
    void ShowMessageError(wxCommandEvent& event);
};

const int ID_PLUS = 101;
const int ID_MINUS = 102;