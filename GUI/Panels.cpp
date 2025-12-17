#include "Panels.h"
#include <iostream>

using namespace std;

LogPanel::LogPanel(wxWindow* parent) : 
	wxPanel(parent)
{
	wxTextCtrl* textDisplay = new wxTextCtrl();
	wxStreamToTextRedirector redirect(textDisplay);

	bool finished;
	int x = 0;
	while (true) {
		finished = false;
		cout << "Lap " << x++ << endl;
		finished = true;
	}
}

ScanInProgressPanel::ScanInProgressPanel(wxWindow* parent) :
	wxPanel(parent)
{
	// Start a timer
	timer = new wxTimer(this, ID_SCANINPROGRESS_TIMER);
	timer->Start(500, wxTIMER_CONTINUOUS);
	Bind(wxEVT_TIMER, &ScanInProgressPanel::OnTimer, this, ID_SCANINPROGRESS_TIMER);

	wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL);
	wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

	// Progress bar
	progressGauge = new wxGauge(this, wxID_ANY, 100, wxDefaultPosition, wxSize(100, 20), wxGA_HORIZONTAL);
	progressGauge->SetValue(0);

	// Progress info text
	wxStaticText* statusText = new wxStaticText(this, wxID_ANY, _("Scan in progress..."), wxDefaultPosition, wxDefaultSize);
	wxTextCtrl* filesScannedText = new wxTextCtrl(this, wxID_ANY, "0", wxDefaultPosition, wxDefaultSize, wxTE_READONLY);
	
	hbox->Add(progressGauge, 0, wxEXPAND | wxALL, 5);
	vbox->Add(statusText, 0, wxEXPAND | wxBOTTOM, 5);
	vbox->Add(filesScannedText, 0, wxEXPAND);
	hbox->Add(vbox, 1, wxEXPAND | wxTOP | wxRIGHT | wxBOTTOM, 5);

	this->SetSizer(hbox);
}

void ScanInProgressPanel::OnTimer(wxTimerEvent& event)
{
	progressGauge->SetValue((progressGauge->GetValue() + 10) % 110);
}

LaunchScanPanel::LaunchScanPanel(wxWindow* parent) : wxPanel(parent)
{
	wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

	// Configuring contents
	wxStaticText* text1 = new wxStaticText(this, wxID_ANY, _("Configure your scan settings"));
	text1->SetFont(text1->GetFont().Scale(1.1));

	wxBoxSizer* hbox = new wxBoxSizer(wxHORIZONTAL);
	text2 = new wxStaticText(this, wxID_ANY, _("Setting 1: "));
	wxRadioButton* choiceA = new wxRadioButton(this, wxID_ANY, "A", wxDefaultPosition, wxDefaultSize, wxRB_GROUP);
	wxRadioButton* choiceB = new wxRadioButton(this, wxID_ANY, "B");

	wxButton* launchButton = new wxButton(this, 3, _("Launch"));

	// Configuring sizers
	vbox->Add(text1, 0, wxEXPAND | wxALL, 5);

	hbox->Add(text2, 0, wxEXPAND | wxRIGHT, 3);
	hbox->Add(choiceA, 0, wxEXPAND | wxRIGHT, 3);
	hbox->Add(choiceB, 0, wxEXPAND);
	vbox->Add(hbox, 0, wxEXPAND | wxLEFT | wxBOTTOM | wxRIGHT, 5);

	vbox->Add(launchButton, 0, wxEXPAND | wxLEFT | wxBOTTOM | wxRIGHT, 5);
	Bind(wxEVT_BUTTON, &LaunchScanPanel::OnLaunchButtonClick, this, 3);

	this->SetSizer(vbox);
}

void LaunchScanPanel::OnLaunchButtonClick(wxCommandEvent& event)
{
	event.Skip();
}
