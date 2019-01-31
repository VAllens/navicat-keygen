#include "StdAfx.h"
#include "Patch.h"
#include "Helper.h"

#define IDR_PUBKEY TEXT("ACTIVATIONPUBKEY")

LPCSTR CPatch::pPublic = "-----BEGIN PUBLIC KEY-----\r\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n\
qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n\
a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n\
R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n\
WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n\
YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n\
awIDAQAB\r\n\
-----END PUBLIC KEY-----\r\n";


HRESULT CPatch::Patch(LPCTSTR szPath, VS_FIXEDFILEINFO *pVer)
{
    // 导入私钥
    CHelpPtr<BIO> pBIO = BIO_new(BIO_s_mem());

    HMODULE hModule = _Module.GetResourceInstance();
    HRSRC hSrc = ::FindResource(hModule, MAKEINTRESOURCE(IDR_RSAKEY), RT_RCDATA);
    HGLOBAL hRes = ::LoadResource(hModule, hSrc);
    BIO_write(pBIO, ::LockResource(hRes), SizeofResource(hModule, hSrc));
    ::FreeResource(hRes);

    CHelpPtr<RSA> pRSA = PEM_read_bio_RSAPrivateKey(pBIO, NULL, NULL, NULL);
    PSTR pData = NULL;
    PEM_write_bio_RSA_PUBKEY(pBIO, pRSA);
    int nLen = BIO_get_mem_data(pBIO, &pData);
  
    if (HIWORD(pVer->dwFileVersionMS) <= 0xB)
    {
        return Patch0(szPath, pData, nLen);
    }
    
    if (LOWORD(pVer->dwFileVersionMS) == 0 && HIWORD(pVer->dwFileVersionLS) < 0x19)
    {
        return Patch0(szPath, pData, nLen); // Ver 12.0.0 ~ 12.0.24
    }

    HRESULT hr = Load(szPath);
    if (FAILED(hr)) return hr;

    hr = HRESULT_FROM_WIN32(Patch1(pData, nLen)); // Ver 12.0.25 ~ 12.1.10
    if (FAILED(hr)) return hr;

    if (LOWORD(pVer->dwFileVersionMS) == 1)
    {
        if (HIWORD(pVer->dwFileVersionLS) == 0xB)
        {
            hr = HRESULT_FROM_WIN32(Patch2(pData, nLen)); // Ver 12.1.11
        }
        else if (HIWORD(pVer->dwFileVersionLS) > 0xB)
        {
            hr = HRESULT_FROM_WIN32(Patch3(pData, nLen));
        }
    }
    return hr;
}

/*
 * Impl of CPatch
 */
HRESULT CPatch::Load(LPCTSTR szPath)
{
    HRESULT hr = S_OK;

    HR_CHECK(hFile.Create(szPath, GENERIC_ALL, FILE_SHARE_READ, OPEN_EXISTING));
    HR_CHECK(pView.MapFile(hFile, 0, 0, PAGE_READWRITE, FILE_MAP_READ | FILE_MAP_WRITE));

    PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pView.GetData());
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) return ERROR_BAD_EXE_FORMAT;

    pINH = reinterpret_cast<PIMAGE_NT_HEADERS>(pView + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE) return ERROR_BAD_EXE_FORMAT;

    pISN = reinterpret_cast<PIMAGE_SECTION_HEADER>(pView + pIDH->e_lfanew +
        sizeof(pINH->Signature) + sizeof(pINH->FileHeader) + pINH->FileHeader.SizeOfOptionalHeader);
exit:
    return hr;
}

PIMAGE_SECTION_HEADER CPatch::Section(LPCSTR szName)
{
    for (WORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        if (memcmp(pISN[i].Name, szName, strlen(szName)) == 0)
        {
            return pISN + i;
        }
    }
    return NULL;
}

PBYTE CPatch::RVA(UINT64 uRva)
{
    WORD i = 0;
    for (; i < pINH->FileHeader.NumberOfSections - 1; i++)
    {
        if (pISN[i + 1].VirtualAddress > uRva)
        {
            PBYTE pRaw = pView + pISN[i].PointerToRawData;
            return pRaw + uRva - pISN[i].VirtualAddress;
        }
    }
    if (pISN[i].VirtualAddress + pISN[i].SizeOfRawData < uRva)
        return NULL;
    PBYTE pRaw = pView + pISN[i].PointerToRawData;
    return pRaw + uRva - pISN[i].VirtualAddress;
}

int CPatch::TrimKey(LPCSTR pSrc, PSTR pDst, int nKey)
{
    int i = 0, j = 0;
    while (pSrc[i] != '\n') i++;
    for (; i < nKey; i++)
    {
        while (pSrc[i] == '\n' || pSrc[i] == '\r') i++;
        if (pSrc[i] == '-') break;
        pDst[j++] = pSrc[i];
    }
    pDst[j] = '\0';
    return j;
}

HRESULT CPatch::Patch0(LPCTSTR szPath, LPVOID pData, DWORD uSize)
{
    HRESULT hr = S_OK;
    HANDLE hUpdate = ::BeginUpdateResource(szPath, FALSE);
    BOOL_CHECK(hUpdate);
    BOOL_CHECK(::UpdateResource(hUpdate, RT_RCDATA, IDR_PUBKEY, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), pData, uSize));
exit:
    if (NULL != hUpdate && !::EndUpdateResource(hUpdate, FAILED(hr)))
        hr = HRESULT_FROM_WIN32(::GetLastError());
    return hr;
}
