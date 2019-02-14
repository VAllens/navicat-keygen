#include "patch.h"
#include "helper.h"
#include <vector>

#if defined(_WIN32)

int CPatch::Patch2(char *key, int n)
{
    std::string pub = TrimKey(public_key.c_str());

    return 0;
}

#elif defined(__APPLE__)

int CPatch::Patch2(char *key, int n)
{
    CAutoPtr<char> pub = (char*)malloc(public_key.length());
    n = 0;
    for (size_t i = 0; i < public_key.length(); i++)
    {
        if (public_key[i] == '\n') pub[n++] = '\0';
        else if (public_key[i] != '\r') pub[n++] = public_key[i]; 
    }
    uint64_t off = Search(sect_string, pub, n);
    if (!off) return -1;
    printf("patch2 found 0x%.8llx len %d\n", off, n);
    // begin patch
    for (int i = 0; i < n; i++) if (pub[i] == '\n') key[i] = '\0';
    memcpy(Rva(off), key, n);
    return 0;
}
#endif