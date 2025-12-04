// For compilers that support precompilation, includes "wx/wx.h".
#include <wx/wxprec.h>

#ifndef WX_PRECOMP
	#include <wx/wx.h>
#endif

#include <wx/simplebook.h>


class LogPanel : public wxPanel
{
public:
	LogPanel(wxWindow* parent);	// Seems like this pointer is obligatory?
};

class ScanInProgressPanel : public wxPanel
{
public:
	ScanInProgressPanel(wxWindow* parent);

private:
	void OnTimer(wxTimerEvent& event);

private:
	wxTimer* timer;
	wxGauge* progressGauge;
	enum {ID_SCANINPROGRESS_TIMER = 50};
};

class LaunchScanPanel : public wxPanel {
public:
	LaunchScanPanel(wxWindow* parent);

private:
	wxStaticText* text2;

	void OnLaunchButtonClick(wxCommandEvent& event);
};
//class filesystemScanBook : public wxSimplebook
//{
//public:
//	filesystemScanBook(wxWindow* parent);
//};
