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
#define sect_code "__text"
#define sect_string "__cstring"

#endif

class CPatch
{
public:
    typedef struct 
    {
        const char *name;
        uint64_t rip;
        const uint8_t *ptr;
        size_t size;
    } sec_ctx;

    enum {
        UNKNOWN,
        I386,
        AMD64
    };
public:
    bool Open(const char *path);
    void Close();

    int Patch2(char *key, int n);
    int Patch3(char *key, int n);
   
    uint8_t* Rva(uint64_t rva);
    sec_ctx Section(const char *name);
    // find code block occurs in section
    uint64_t Search(const char *name, const void *code, int s, int64_t off = 0);
    // trim pem header
    static std::string TrimKey(const char *src);

private:
    std::map<uint64_t, sec_ctx> sects;
    static const std::string public_key;

    void* pView;
#if defined(_WIN32)
    void *hFile;
    void *hMapping;
#else
    int fd;
    long length;
public:
    uint8_t *dyld;
#endif
public:
    CPatch();
    ~CPatch() { Close(); }
};

#endif // _PATCH_H_