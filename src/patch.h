#ifndef _PATCH_H_
#define _PATCH_H_

#include <platform.h>
#include <string>
#include <map>

#if defined(_WIN32)

#define strcmpi stricmp
#define sect_code ".text"
#define sect_string ".rdata"

#elif defined(__APPLE__)

#define strcmpi strcasecmp
#define sect_code "__TEXT"
#define sect_string "__cstring"

#endif

class CPatch
{
public:
    enum {
        UNKNOWN,
        I386,
        AMD64
    };
public:
    bool Open(const char *path);
    void Close();

    int Patch2();
    int Patch3();
   
    uint8_t* Rva(uint64_t rva);
    // find code block occurs in section
    uint64_t Search(const char *name, const void *code, int s, int64_t off = 0);
    // trim pem header
    static std::string TrimKey(const char *src);

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
    static const std::string public_key;
public:
    CPatch();
    ~CPatch() { Close(); }
};

#endif // _PATCH_H_