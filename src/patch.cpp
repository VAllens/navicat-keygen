#include "patch.h"

const char * CPatch::public_key = "-----BEGIN PUBLIC KEY-----\r\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n\
qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n\
a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n\
R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n\
WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n\
YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n\
awIDAQAB\r\n\
-----END PUBLIC KEY-----\r\n";

#if defined(_WIN32)
#include <windows.h>

CPatch::CPatch() : pView(NULL),
hFile(NULL), hMapping(NULL)
{
}
#elif defined(__APPLE__)
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <mach-o/loader.h>

static void *_invalid = reinterpret_cast<void*>(-1);

CPatch::CPatch() : pView(_invalid),
fd(-1), length(0)
{
}
#endif

CPatch::~CPatch()
{
}

#if defined(_WIN32)
bool CPatch::Open(const char* pPath)
{
    hFile = ::CreateFile(pPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!hFile) return false;

	hMapping = ::CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) return false;

    pView = ::MapViewOfFileEx(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0, NULL);
    if (!pView) return false;

    PIMAGE_DOS_HEADER pIDH = reinterpret_cast<PIMAGE_DOS_HEADER>(pView);
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) return false;

    uint8_t *p = reinterpret_cast<uint8_t*>(pView) + pIDH->e_lfanew;
    PIMAGE_NT_HEADERS pINH = reinterpret_cast<PIMAGE_NT_HEADERS>(p);
    if (pINH->Signature != IMAGE_NT_SIGNATURE) return false;

    PIMAGE_SECTION_HEADER pISN = reinterpret_cast<PIMAGE_SECTION_HEADER>(p +
        sizeof(pINH->Signature) + sizeof(pINH->FileHeader) + pINH->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < pINH->FileHeader.NumberOfSections; i++, pISN++)
        sects[pISN->VirtualAddress] = (char *)pISN->Name;
    return true;
}

void CPatch::Close()
{
    if (pView != NULL) ::UnmapViewOfFile(pView);
    if (hMapping != NULL) ::CloseHandle(hMapping);
    if (hFile != NULL) ::CloseHandle(hFile);
}

uint8_t* CPatch::Rva(uint64_t rva) 
{
    auto v = sects.lower_bound(rva);
    if (sects.end() == v) return NULL;
    if (v->first != rva) --v;

    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)(v->second);
    uint8_t *p = reinterpret_cast<uint8_t*>(pView) + sec->PointerToRawData;
    return p + rva - sec->VirtualAddress;
}

uint64_t CPatch::FindCode(uint32_t hint, uint32_t range, const void *code, uint32_t size)
{
    PIMAGE_SECTION_HEADER sec = NULL;
    for (auto i = sects.begin(); i != sects.end(); i++)
        if (_strcmpi(".text", i->second) == 0)
        {
            sec = (PIMAGE_SECTION_HEADER)(i->second);
            break;
        }
    if (!sec) return -2;

    uint8_t* p = reinterpret_cast<uint8_t*>(pView) + sec->PointerToRawData;
    for (uint32_t i = 0; i < sec->SizeOfRawData; ++i)
        if (*(uint32_t*)(p + i) == hint)
            for (uint32_t j = i - range; j < i; ++j)
                if (memcmp(p + j, code, size) == 0)
                    return sec->VirtualAddress + j;
    return -1;
}

#elif defined(__APPLE__)

bool CPatch::Open(const char* pPath)
{
    fd = open(pPath, O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) return false;

    struct stat fd_stat = {};
    if (fstat(fd, &fd_stat) != 0) return false;

    length = fd_stat.st_size;
    pView = mmap(NULL, fd_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (_invalid == pView) return false;

    mach_header_64 *mh = (mach_header_64 *)pView;
    if (mh->magic != MH_MAGIC_64) return false;

    uint8_t *p = reinterpret_cast<uint8_t*>(mh) + sizeof(mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_command *lc = (load_command *)p;
        if (lc->cmd == LC_SEGMENT_64)
        {
            segment_command_64 *sc = (segment_command_64 *)p;
            // printf("segment (%s) offset 0x%llx size 0x%llx nsec %d\n", sc->segname, sc->fileoff, sc->filesize, sc->nsects);
            section_64 *sec = (section_64 *)(p + sizeof(segment_command_64));
            for (uint32_t j = 0; j < sc->nsects; j++, sec++)
                sects[sec->addr] = sec->sectname;
        }
        p += lc->cmdsize;
    }
    return true;
}

void CPatch::Close()
{
    if (pView != _invalid) munmap(pView, length);
    if (fd > 0) close(fd);
}

uint8_t* CPatch::Rva(uint64_t rva) 
{
    auto v = sects.lower_bound(rva);
    if (sects.end() == v) return NULL;
    if (v->first != rva) --v;

    section_64 *sec = (section_64 *)(v->second);
    uint8_t *p = reinterpret_cast<uint8_t*>(pView) + sec->offset;
    return p + rva - sec->addr;
}

uint64_t CPatch::FindCode(uint32_t hint, uint32_t range, const void *code, uint32_t size)
{
    section_64 *sec = NULL;
    for (auto i = sects.begin(); i != sects.end(); i++)
        if (strcasecmp(SECT_TEXT, i->second) == 0)
        {
            sec = (section_64 *)(i->second);
            break;
        }
    if (!sec) return -2;

    printf("section (%s) offset 0x%x addr 0x%llx size 0x%llx => %llx\n", 
        sec->sectname, sec->offset, sec->addr, sec->size, sec->addr - sec->offset);

    uint8_t* p = reinterpret_cast<uint8_t*>(pView) + sec->offset;
    for (uint32_t i = 0; i < sec->size; ++i)
        if (*(uint32_t*)(p + i) == hint)
            for (uint32_t j = i - range; j < i; ++j)
                if (memcmp(p + j, code, size) == 0)
                    return sec->addr + j;
    return -1;
}
#endif

std::string CPatch::TrimKey(const char *src)
{
    std::string s;
    int i = 0;
    while (src[i] != '\n') i++;
    for (; src[i]; i++)
    {
        while (src[i] == '\n' || src[i] == '\r') i++;
        if (src[i] == '-') break;
        s.push_back(src[i]);
    }
    return s;
}