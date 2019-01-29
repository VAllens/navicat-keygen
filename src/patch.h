#ifndef _PATCH_H_
#define _PATCH_H_

#include <platform.h>
#include <map>
#include <string>

class CPatch
{
public:
    bool Open(const char *path);
    void Close();
    uint8_t* Rva(uint64_t rva);
    // count string occurs in code section
    int Search(const char *sec, void *p, uint32_t s) { return 0; }
    static std::string TrimKey(const char *src);

    int Patch3();
    uint64_t FindCode(uint32_t hint, uint32_t range, 
        const void *code, uint32_t size);

private:
    void* pView;
#if defined(_WIN32)
    void *hFile;
    void *hMapping;
#else
    int fd;
    long length;
#endif
    std::map<uint64_t, const char*> sects;
    static const char *public_key;
public:
    CPatch();
    ~CPatch();
};

#endif // _PATCH_H_