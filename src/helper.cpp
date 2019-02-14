#include "helper.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

RSA * LoadRSA()
{
    CAutoPtr<BIO> pBIO = BIO_new(BIO_s_mem());
    HMODULE hModule = ::GetModuleHandle(NULL);
    HRSRC hSrc = ::FindResource(hModule, MAKEINTRESOURCE(101), RT_RCDATA);
    HGLOBAL hRes = ::LoadResource(hModule, hSrc);
    BIO_write(pBIO, ::LockResource(hRes), SizeofResource(hModule, hSrc));
    ::FreeResource(hRes);
    return PEM_read_bio_RSAPrivateKey(pBIO, NULL, NULL, NULL);
}