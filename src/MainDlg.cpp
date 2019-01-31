#include "StdAfx.h"
#include "MainDlg.h"
#include "Patch.h"

CMainDlg::CMainDlg() : hThread(NULL)
{
}

CMainDlg::~CMainDlg()
{
}

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
{
    HRESULT hr = S_OK;
    TCHAR szUser[MAX_PATH] = { 0 }, szOrg[MAX_PATH] = { 0 };
    DWORD uSize = 0;
    HWND hCombox = NULL;
    ATL::CRegKey hReg;
    // 设置窗体图标
    HICON hIcon = ::LoadIcon(_Module.GetResourceInstance(), MAKEINTRESOURCE(IDR_MAIN));
    BOOL_CHECK(hIcon);
    SetIcon(hIcon);
    BOOL_CHECK(CenterWindow());
    GetWindowText(szTitle);
    // 获取用户名 组织名
    HR_CHECK(hReg.Open(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), KEY_QUERY_VALUE | KEY_WOW64_64KEY));
    uSize = _countof(szOrg);
    HR_CHECK(hReg.QueryStringValue(TEXT("RegisteredOrganization"), szOrg, &uSize));
    uSize = _countof(szUser);
    HR_CHECK(hReg.QueryStringValue(TEXT("RegisteredOwner"), szUser, &uSize));
    SetDlgItemText(IDC_NAME, szUser);
    SetDlgItemText(IDC_ORGANIZATION, szOrg);
    // 限制文本长度
    SendDlgItemMessage(IDC_NAME, EM_SETLIMITTEXT, MAX_PATH);
    SendDlgItemMessage(IDC_ORGANIZATION, EM_SETLIMITTEXT, MAX_PATH);

    // 版本选择
    hCombox = GetDlgItem(IDC_VERSION);
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("v11")), 0xB0);
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("v12")), 0xC0);
    ComboBox_SetCurSel(hCombox, 1);
    OnChanged(0, 0, hCombox, bHandled);

    // 语言选择
    hCombox = GetDlgItem(IDC_LANGUAGE);
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("English")), 0x88AC); // 英语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("简体中文")), 0x32CE); // 简体中文
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("繁體中文")), 0x99AA); // 繁体中文
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("日本語")), 0x82AD); // 日语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Polski")), 0x55BB); // 波兰语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Español")), 0x10AE); // 西班牙语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Français")), 0x20FA); // 法语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Deutsch")), 0x60B1); // 德语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("한국어")), 0x60B5); // 朝鲜语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Русский")), 0x16EE); // 俄语
    ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Português")), 0x49CD); // 葡萄牙语
    ComboBox_SetCurSel(hCombox, 1);
exit:
    return TRUE;
}

LRESULT CMainDlg::OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    DestroyWindow();
    ::PostQuitMessage(wID);
    return 0;
}

LRESULT CMainDlg::OnPatch(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    ATL::CRegKey hReg;
    HRESULT hr = hReg.Open(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"), KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY);
    if (FAILED(hr)) return hr;

    TCHAR szPath[MAX_PATH] = {};
    DWORD uSize = _countof(szFile);
    for (DWORD i = 0; !hReg.EnumKey(i, szFile, &uSize); i++)
    {
        uSize = _countof(szFile);
        if (_tcsstr(szFile, TEXT("Navicat")) && SUCCEEDED(hReg.Open(hReg, szFile, KEY_QUERY_VALUE | KEY_WOW64_64KEY)))
        {
            if (SUCCEEDED(hReg.QueryStringValue(TEXT("InstallLocation"), szPath, &uSize)))
            {
                break;
            }
        }
    }
    // 选择主程序路径
    OPENFILENAME ofn = { sizeof(OPENFILENAME) };
    ofn.hwndOwner = m_hWnd;
    ofn.lpstrFilter = TEXT("Navicat\0navicat.exe;modeler.exe\0");
    ofn.lpstrInitialDir = szPath;
    ofn.Flags = OFN_HIDEREADONLY | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = _countof(szFile);
    ZeroMemory(szFile, sizeof(szFile));
    if (!::GetOpenFileName(&ofn)) return FALSE;

    if (NULL != hThread && ::WaitForSingleObject(hThread, 0) == WAIT_TIMEOUT)
    {
        CAtlString szText;
        szText.LoadString(IDS_BUSY);
        return MessageBox(szText, szTitle, MB_ICONWARNING);
    }

    for (int i = IDC_GENERATE; i <= IDC_ORGANIZATION; i++)
        GetDlgItem(i).EnableWindow(FALSE);
    hThread = ::CreateThread(NULL, 0, CMainDlg::ThreadPatch, this, 0, NULL);
    return TRUE;
}

LRESULT CMainDlg::OnChanged(WORD /*wNotifyCode*/, WORD /*wID*/, HWND hWndCtl, BOOL& /*bHandled*/)
{
    // 版本选择
    int nIndex = ComboBox_GetCurSel(hWndCtl);
    HWND hCombox = GetDlgItem(IDC_PRODUCT);
    int nProduct = ComboBox_GetCurSel(hCombox);
    ComboBox_ResetContent(hCombox);
    if (nIndex == Navicat12)
    {
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat Premium")), 0x65);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for MySQL")), 0x68);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for PostgreSQL")), 0x6C);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for Oracle")), 0x70);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for SQL Server")), 0x74);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for SQLite")), 0x78);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for MariaDB")), 0x7C);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat Premium Essentials")), 0x67);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for MongoDB")), 0x80);
    }
    else if (nIndex == Navicat11)
    {
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat Premium")), 0x15);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for MySQL")), 0x01);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for PostgreSQL")), 0x04);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for Oracle")), 0x10);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for SQL Server")), 0x24);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for SQLite")), 0x1D);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat for MariaDB")), 0x4D);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat Premium Essentials")), 0x3A);
        ComboBox_SetItemData(hCombox, ComboBox_AddString(hCombox, TEXT("Navicat Data Modeler")), 0x47);
    }
    return ComboBox_SetCurSel(hCombox, nProduct > 0 ? nProduct : 0);
}

DWORD CALLBACK CMainDlg::ThreadPatch(LPVOID lpParam)
{
    CMainDlg *pDlg = reinterpret_cast<CMainDlg*>(lpParam);
    HRESULT hr = S_OK;
    CAtlString szBackup;
 
    UINT uLen = ::GetFileVersionInfoSize(pDlg->szFile, NULL);
    PVOID pInfo = ::LocalAlloc(LPTR, uLen);
    BOOL_CHECK(::GetFileVersionInfo(pDlg->szFile, 0, uLen, pInfo));
    // 获取主程序版本号
    VS_FIXEDFILEINFO *pVersion = NULL;
    BOOL_CHECK(::VerQueryValue(pInfo, TEXT("\\"), (LPVOID*)&pVersion, &uLen));
    HWND hCombox = pDlg->GetDlgItem(IDC_VERSION);
    if (HIWORD(pVersion->dwFileVersionMS) == 0x0C)
    {
        if (LOWORD(pVersion->dwFileVersionMS) > 0 || HIWORD(pVersion->dwFileVersionLS) >= 0x19)
        {
            ::PathRemoveFileSpec(pDlg->szFile);
            ::PathCombine(pDlg->szFile, pDlg->szFile, TEXT("libcc.dll"));
        }
        ComboBox_SetCurSel(hCombox, Navicat12);
    }
    else
    {
        ComboBox_SetCurSel(hCombox, Navicat11);
    }
    BOOL bCopy = FALSE;
    pDlg->OnChanged(IDC_VERSION, CBN_SELCHANGE, hCombox, bCopy);
    // 获取产品名称
    LPCWSTR szName = NULL;
    BOOL_CHECK(::VerQueryValue(pInfo, TEXT("\\StringFileInfo\\040904b0\\ProductName"), (LPVOID*)&szName, &uLen));
    hCombox = pDlg->GetDlgItem(IDC_PRODUCT);
    if (CB_ERR == ComboBox_SelectString(hCombox, -1, szName))
    {
        ::LocalFree(pInfo);
        return pDlg->PostMessage(WM_THREAD_END, hr);
    }
    // 备份主程序
    szBackup = pDlg->szFile;
    szBackup.Append(TEXT(".bak"));
    bCopy = ::CopyFile(pDlg->szFile, szBackup, TRUE);
    {
        CPatch s;
        // 更新主程序RSA公钥
        hr = s.Patch(pDlg->szFile, pVersion);
    }
    if (bCopy && hr != S_OK) ::MoveFileEx(szBackup, pDlg->szFile, MOVEFILE_REPLACE_EXISTING);
exit:
    if (NULL != pInfo) ::LocalFree(pInfo);
    return pDlg->PostMessage(WM_THREAD_END, hr);
}

LRESULT CMainDlg::OnPatchEnd(UINT /*uMsg*/, WPARAM wParam, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
    for (int i = IDC_GENERATE; i <= IDC_ORGANIZATION; i++)
        GetDlgItem(i).EnableWindow(TRUE);

    ::FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, DWORD(wParam), 0, szFile, _countof(szFile), NULL);
    return MessageBox(szFile, szTitle, SUCCEEDED(wParam) ? MB_ICONINFORMATION : MB_ICONERROR);;
}