#ifndef _MAIN_DLG_H_
#define _MAIN_DLG_H_

#define WM_THREAD_END WM_USER + 16

class CMainDlg : public CDialogImpl<CMainDlg>
{
public:
    enum { IDD = IDR_MAIN };

    BEGIN_MSG_MAP(CMainDlg)
        MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
        COMMAND_ID_HANDLER(IDCANCEL, OnCancel)
        COMMAND_ID_HANDLER(IDC_PATCH, OnPatch)
        COMMAND_ID_HANDLER(IDC_GENERATE, OnKeyGen)
        COMMAND_ID_HANDLER(IDC_ACTIVATE, OnActive)
        COMMAND_HANDLER(IDC_VERSION, CBN_SELCHANGE, OnChanged)
        MESSAGE_HANDLER(WM_THREAD_END, OnPatchEnd)
    END_MSG_MAP()

public:
    LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
    LRESULT OnCancel(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
    LRESULT OnPatch(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
    LRESULT OnKeyGen(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
    LRESULT OnActive(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
    LRESULT OnChanged(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
    LRESULT OnPatchEnd(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);

private:
    enum {
        Navicat11 = 0,
        Navicat12
    };

    HRESULT Block();
    static DWORD CALLBACK ThreadPatch(LPVOID lpParam);

private:
    CAtlString szTitle;
    TCHAR szFile[MAX_PATH];
    HANDLE hThread;

public:
    CMainDlg();
    virtual ~CMainDlg();
};

#endif // _MAIN_DLG_H_