#include "StdAfx.h"
#include "MainDlg.h"
#include "Patch.h"
#include "Helper.h"

#include <openssl/des.h>

static TCHAR table[] = TEXT("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
static BYTE des_key[] = { 0x64, 0xAD, 0xF3, 0x2F, 0xAE, 0xF2, 0x1A, 0x27 };

LRESULT CMainDlg::OnKeyGen(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    HWND hCombox = NULL;
    BYTE tmp_key[18] = { 0x68, 0x2a };   //  must start with 0x68, 0x2a
    // random
    *((PDWORD)(tmp_key + 2)) = ::GetTickCount();
    // language
    hCombox = GetDlgItem(IDC_LANGUAGE);
    *((PWORD)(tmp_key + 5)) = (WORD)ComboBox_GetItemData(hCombox, ComboBox_GetCurSel(hCombox));
    // product id
    hCombox = GetDlgItem(IDC_PRODUCT);
    tmp_key[7] = (BYTE)ComboBox_GetItemData(hCombox, ComboBox_GetCurSel(hCombox));
    // version
    hCombox = GetDlgItem(IDC_VERSION);
    //  High 4-bits = version number. Low 4-bits doesn't know, but can be used to delay activation time.
    tmp_key[8] = (BYTE)ComboBox_GetItemData(hCombox, ComboBox_GetCurSel(hCombox));
    tmp_key[9] = 0x32;   //  0xfd, 0xfc, 0xfb if you want to use not-for-resale license.

    DES_key_schedule schedule;
    DES_set_key_unchecked(&des_key, &schedule);
    DES_ecb_encrypt((const_DES_cblock*)(tmp_key + 2), (DES_cblock*)(tmp_key + 2), &schedule, DES_ENCRYPT);

    HGLOBAL hMem = ::GlobalAlloc(GHND, 20 * sizeof(TCHAR));
    LPTSTR szSN = (LPTSTR)::GlobalLock(hMem);
    int n = 0;
    // 生成序列号
    szSN[n++] = table[tmp_key[0] >> 3];
    szSN[n++] = table[(tmp_key[0] & 0x07) << 2 | tmp_key[1] >> 6];
    szSN[n++] = table[tmp_key[1] >> 1 & 0x1F];
    szSN[n++] = table[(tmp_key[1] & 0x1) << 4 | tmp_key[2] >> 4];
    szSN[n++] = TEXT('-');
    szSN[n++] = table[(tmp_key[2] & 0xF) << 1 | tmp_key[3] >> 7];
    szSN[n++] = table[tmp_key[3] >> 2 & 0x1F];
    szSN[n++] = table[tmp_key[3] << 3 & 0x1F | tmp_key[4] >> 5];
    szSN[n++] = table[tmp_key[4] & 0x1F];
    szSN[n++] = TEXT('-');
    szSN[n++] = table[tmp_key[5] >> 3];
    szSN[n++] = table[(tmp_key[5] & 0x07) << 2 | tmp_key[6] >> 6];
    szSN[n++] = table[tmp_key[6] >> 1 & 0x1F];
    szSN[n++] = table[(tmp_key[6] & 0x1) << 4 | tmp_key[7] >> 4];
    szSN[n++] = TEXT('-');
    szSN[n++] = table[(tmp_key[7] & 0xF) << 1 | tmp_key[8] >> 7];
    szSN[n++] = table[tmp_key[8] >> 2 & 0x1F];
    szSN[n++] = table[tmp_key[8] << 3 & 0x1F | tmp_key[9] >> 5];
    szSN[n++] = table[tmp_key[9] & 0x1F];
    szSN[n++] = TEXT('\0');

    SetDlgItemText(IDC_SERIAL, szSN);
    // 复制到剪贴板
    if (OpenClipboard())	//复制到剪贴板
    {
        ::EmptyClipboard();
#if defined(UNICODE)
        ::SetClipboardData(CF_UNICODETEXT, hMem);
#else
        ::SetClipboardData(CF_TEXT, hMem);
#endif
        ::CloseClipboard();
    }
  
    // 自动填充序列号
    HWND hForm = ::FindWindowEx(NULL, NULL, TEXT("TRegistrationSubForm"), NULL);
    if (!::IsWindow(hForm)) hForm = ::FindWindowEx(NULL, NULL, TEXT("TRegistrationForm"), NULL);;
    if (!::IsWindow(hForm)) return FALSE;

    HWND hPanel = NULL;
    while (::IsWindow(hPanel = ::FindWindowEx(hForm, hPanel, TEXT("TPanel"), NULL)))
    {
        HWND hChild = NULL, hEdit = NULL;
        while (::IsWindow(hChild = ::FindWindowEx(hPanel, hEdit, TEXT("TEdit"), NULL)))
        {
            hEdit = hChild;
        }
        ::PostMessage(hEdit, WM_PASTE, 0, NULL);
    }
    ::GlobalFree(hMem);
    return TRUE;
}


/*
* 屏蔽激活服务器
*/
HRESULT CMainDlg::Block()
{
    HRESULT hr = S_OK;
    LPCSTR szServer = "\r\n127.0.0.1\tactivate.navicat.com";
    CAtlString szPath;
    CAtlFile hHost;
    CAtlFileMapping<CHAR> pHost;
    BOOL_CHECK(::GetSystemDirectory(szPath.GetBuffer(MAX_PATH), MAX_PATH));
    BOOL_CHECK(::PathCombine(szPath.GetBuffer(), szPath, TEXT("drivers\\etc\\hosts")));
    HR_CHECK(hHost.Create(szPath, GENERIC_ALL, FILE_SHARE_READ, OPEN_EXISTING));
    HR_CHECK(pHost.MapFile(hHost));
    // 判断是否在hosts屏蔽
    LPSTR pCur = strstr(pHost, szServer);
    if (NULL != pCur)
    {
        szPath.LoadString(IDS_FORMNOTFOUND);
        return MessageBox(szPath, szTitle, MB_ICONWARNING);
    }
    szPath.LoadString(IDS_BLOCK);
    BOOL_CHECK(MessageBox(szPath, szTitle, MB_ICONQUESTION | MB_OKCANCEL) == IDOK);
    HR_CHECK(hHost.Seek(0, FILE_END));
    HR_CHECK(hHost.Write(szServer, (DWORD)strlen(szServer)));
    HR_CHECK(hHost.Flush());
    // 刷新DNS缓存
    HMODULE hDns = ::LoadLibrary(TEXT("DNSAPI.dll"));
    BOOL_CHECK(hDns);
    FARPROC pFlush = ::GetProcAddress(hDns, "DnsFlushResolverCache");
    if (NULL != pFlush) pFlush();
    ::FreeLibrary(hDns);
exit:
    return hr;
}

BOOL CALLBACK EnumChild(HWND hWnd, LPARAM lParam)
{
    DWORD dwStyle = ::GetWindowLong(hWnd, GWL_STYLE);
    if (!(dwStyle & WS_VSCROLL)) return TRUE;

    CAtlString *pLic = (CAtlString *)lParam;
    if (dwStyle & ES_READONLY)
    {
        DWORD uSize = (DWORD)::SendMessage(hWnd, WM_GETTEXTLENGTH, 0, 0L);
        LPTSTR szText = pLic->GetBufferSetLength(uSize);
        ::SendMessage(hWnd, WM_GETTEXT, uSize + 1, (LPARAM)szText);
    }
    else if (pLic->GetLength() > 0)
    {
        ::SendMessage(hWnd, WM_SETTEXT, 0, (LPARAM)pLic->GetBuffer());
    }
    return TRUE;
}
/*
* 生成许可文件
*/
HRESULT GenLic(RSA *pRSA, const CAtlStringA& szName, const CAtlStringA& szOrg, CAtlString& szLic)
{
    HRESULT hr = S_OK;
    CHeapPtr<BYTE> pBin;
    CHeapPtr<CHAR> pText;

    DWORD nBin = szLic.GetLength() * 2 + strlen(szName) + strlen(szOrg);
    pBin.AllocateBytes(nBin);
    BOOL_CHECK(::CryptStringToBinary(szLic, szLic.GetLength(), CRYPT_STRING_BASE64, pBin, &nBin, NULL, NULL));

    DWORD nText = nBin * 2;
    pText.AllocateBytes(nText);
    if (!RSA_private_decrypt(nBin, pBin, (PBYTE)(PSTR)pText, pRSA, RSA_PKCS1_PADDING)) return E_FAIL;

    /* parse json data */
    PSTR pCur = strstr(pText, "\"P\":\"");
    if (NULL == pCur) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    nText = sprintf_s(pCur, pText + nText - pCur, "\"N\":\"%s\", \"O\":\"%s\", \"T\":%d}", szName, szOrg, time(NULL));
 
    /* encode response data */
    nBin = RSA_private_encrypt(nText + int(pCur - pText), (PBYTE)(PSTR)pText, pBin, pRSA, RSA_PKCS1_PADDING);
    nText = nBin * 2;
    BOOL_CHECK(::CryptBinaryToString(pBin, nBin, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, szLic.GetBufferSetLength(nText), &nText));
exit:
    return hr;
}

HRESULT ExportLic(RSA *pRSA, const CAtlStringA& szName, const CAtlStringA& szOrg, LPCTSTR szSN, HWND hWnd)
{
    // 选择许可文件路径
    TCHAR szPath[MAX_PATH] = TEXT("license_file");
    OPENFILENAME ofn = { sizeof(OPENFILENAME), hWnd };
    ofn.lpstrFilter = TEXT("license_file\0");
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_EXPLORER;
    ofn.lpstrFile = szPath;
    ofn.nMaxFile = _countof(szPath);
    if (!::GetSaveFileName(&ofn)) return S_OK;

    CHeapPtr<BYTE> pBin;
    CAtlStringA pText;
    /* create json data */
    pText.Format("{\"K\":\"%S\", \"N\":\"%s\", \"O\":\"%s\", \"T\":%d}", szSN, szName, szOrg, time(NULL));
    pBin.AllocateBytes(pText.GetLength() * 2);
    DWORD nLic = RSA_private_encrypt(pText.GetLength(), (PBYTE)pText.GetString(), pBin, pRSA, RSA_PKCS1_PADDING);

    // save license file
    HRESULT hr = S_OK;
    CAtlFile hLic;
    HR_CHECK(hLic.Create(szPath, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS));
    HR_CHECK(hLic.Write(pBin, nLic));
exit:
    return hr;
}


LRESULT CMainDlg::OnActive(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
    TCHAR szPath[MAX_PATH] = { 0 };
    CAtlString szLic;
    HWND hForm = NULL;
    int nIndex = (int)SendDlgItemMessage(IDC_VERSION, CB_GETCURSEL);
    if (nIndex == Navicat12)
    {
        hForm = ::FindWindowEx(NULL, NULL, TEXT("TManualActivationSubForm"), NULL);
        if (!::IsWindow(hForm)) hForm = ::FindWindowEx(NULL, NULL, TEXT("TManualActivationForm"), NULL);
        if (!::IsWindow(hForm)) return Block();
        // 获取注册信息
        ::EnumChildWindows(hForm, EnumChild, (LPARAM)&szLic);
    }
    else if (nIndex == Navicat11)
    {
        hForm = ::FindWindowEx(NULL, NULL, TEXT("TRegistrationForm"), NULL);
        if (!::IsWindow(hForm)) return Block();
        hForm = ::FindWindowEx(hForm, NULL, TEXT("TPanel"), NULL);
        if (!::IsWindow(hForm)) return Block();
        HWND hEdit = NULL;
        while (::IsWindow(hEdit = ::FindWindowEx(hForm, hEdit, TEXT("TEdit"), NULL)))
        {
            ::SendMessage(hEdit, WM_GETTEXT, _countof(szPath), (LPARAM)szPath);
            szLic.Insert(0, szPath);
        }
    }
    CAtlString szName, szOrg;
    GetDlgItemText(IDC_NAME, szName);
    GetDlgItemText(IDC_ORGANIZATION, szOrg);

    // load key
    HMODULE hModule = _Module.GetResourceInstance();
    HRSRC hSrc = ::FindResource(hModule, MAKEINTRESOURCE(IDR_RSAKEY), RT_RCDATA);
    HGLOBAL hRes = ::LoadResource(hModule, hSrc);
    // 导入私钥
    CHelpPtr<BIO> pBIO = BIO_new_mem_buf(::LockResource(hRes), SizeofResource(hModule, hSrc));
    CHelpPtr<RSA> pRSA = PEM_read_bio_RSAPrivateKey(pBIO, NULL, NULL, NULL);
    ::FreeResource(hRes);
   
    HRESULT hr = S_OK;
    // 生成许可文件
    if (nIndex == Navicat12)
    {
        hr = GenLic(pRSA, szName.GetString(), szOrg.GetString(), szLic);
        if (SUCCEEDED(hr))
        {
            hr = ::EnumChildWindows(hForm, EnumChild, (LPARAM)&szLic);
        }
    }
    else if (nIndex == Navicat11)
    {
        hr = ExportLic(pRSA, szName.GetString(), szOrg.GetString(), szLic, m_hWnd);
    }

    if (SUCCEEDED(hr)) return S_OK;
    ::FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM, NULL, hr, 0, szPath, _countof(szPath), NULL);
    return MessageBox(szPath, szTitle, SUCCEEDED(hr) ? MB_ICONINFORMATION : MB_ICONERROR);
}