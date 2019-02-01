#include "patch.h"
#include "helper.h"

#if defined(_WIN32)

int CPatch::Patch2()
{
    std::string key = TrimKey(public_key.c_str());

    return 0;
}

#elif defined(__APPLE__)

#include <vector>

int CPatch::Patch2()
{
    CAutoPtr<char> key = (char*)malloc(public_key.length());
    int n = 0;
    for (size_t i = 0; i < public_key.length(); i++)
    {
        if (public_key[i] == '\n') key[n++] = '\0';
        else if (public_key[i] != '\r') key[n++] = public_key[i]; 
    }
    uint64_t off = Search(sect_string, key, n);
    if (!off) return -1;
    printf("patch2 found 0x%.8llx len %d\n", off, n);
    // generate rsa key
    Cipher c;
    char *m = NULL;
    CAutoPtr<BIO> pb = BIO_new(BIO_s_mem());
    if (c.Genkey(pb) <= 0) return -4;
    n = BIO_get_mem_data(pb, &m);
    if (n <= 0) return -3;
    if (c.Save("navicat.pem") <= 0) return -5;
    // begin patch
    for (int i = 0; i < n; i++) if (m[i] == '\n') m[i] = '\0';
    memcpy(Rva(off), m, n);
    return 0;
}
#endif