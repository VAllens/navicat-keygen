#ifndef _PATCH_H_
#define _PATCH_H_

class CPatch
{
private:
    HRESULT Patch0(LPCTSTR szPath, LPVOID pData, DWORD uSize);
    HRESULT Patch1(LPCSTR pData, int nLen);
    HRESULT Patch2(LPCSTR pData, int nLen);
    HRESULT Patch3(LPCSTR pData, int nLen);

public:
    static int TrimKey(LPCSTR pSrc, PSTR pDst, int nKey);
    static LPCSTR pPublic;

    HRESULT Load(LPCTSTR szPath);
    HRESULT Patch(LPCTSTR szPath, VS_FIXEDFILEINFO *pVer);

    PIMAGE_SECTION_HEADER Section(LPCSTR szName);
    PBYTE RVA(UINT64 uRva);

public:
    CAtlFile hFile;
    CAtlFileMapping<BYTE> pView;
    PIMAGE_NT_HEADERS pINH;
    PIMAGE_SECTION_HEADER pISN;
};

class CReloc : protected CRBMap<DWORD, int>
{
public:
    CReloc(PIMAGE_BASE_RELOCATION pIBR);
    bool IsReloc(DWORD uRva, DWORD cbRva);
};
#endif // _PATCH_H_