#include "StdAfx.h"
#include "MainDlg.h"

int Run(int nCmdShow)
{
    CAtlString szText;
    CMainDlg dlgMain;
    // 初始化窗体
    HWND hWnd = dlgMain.Create(HWND_DESKTOP);
    if (NULL == hWnd)
    {
        szText.Format(IDS_ERROR, ::GetLastError());
        return ::MessageBox(HWND_DESKTOP, szText, NULL, MB_ICONERROR);
    }
    dlgMain.ShowWindow(nCmdShow);
    // 主消息循环:
    MSG msg;
    while (::GetMessage(&msg, NULL, 0, 0))
    {
        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    HRESULT hr = ::CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ATLASSERT(SUCCEEDED(hr));

    hr = _Module.Init(NULL, hInstance);
    ATLASSERT(SUCCEEDED(hr));

    int nRet = Run(nCmdShow);
    _Module.Term();

    ::CoUninitialize();
    return nRet;
}