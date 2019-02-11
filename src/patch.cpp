#include "patch.h"

const std::string CPatch::public_key = "-----BEGIN PUBLIC KEY-----\r\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I\r\n\
qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv\r\n\
a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF\r\n\
R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2\r\n\
WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt\r\n\
YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuQ\r\n\
awIDAQAB\r\n\
-----END PUBLIC KEY-----\r\n";

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

CPatch::CPatch() : pView(NULL),
hFile(NULL), hMapping(NULL)
{
}

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
        sects[pISN->VirtualAddress] = sec_ctx{ reinterpret_cast<char*>(pISN->Name), 
            static_cast<uint64_t>(pISN->VirtualAddress), 
            reinterpret_cast<uint8_t*>(pIDH) + pISN->PointerToRawData, 
            static_cast<size_t>(pISN->SizeOfRawData) };
    return true;
}

void CPatch::Close()
{
    if (pView != NULL) ::UnmapViewOfFile(pView);
    if (hMapping != NULL) ::CloseHandle(hMapping);
    if (hFile != NULL) ::CloseHandle(hFile);
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

    uint8_t *p = reinterpret_cast<uint8_t*>(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_command *lc = reinterpret_cast<load_command*>(p);
        if (lc->cmd == LC_SEGMENT_64)
        {
            segment_command_64 *sc = reinterpret_cast<segment_command_64*>(p);
            // printf("segment (%s) offset 0x%llx size 0x%llx nsec %d\n", sc->segname, sc->fileoff, sc->filesize, sc->nsects);
            section_64 *sec = reinterpret_cast<section_64*>(sc + 1);
            for (uint32_t j = 0; j < sc->nsects; j++, sec++)
            {
                sects[sec->addr] = sec_ctx{ sec->sectname, sec->addr, 
                    reinterpret_cast<uint8_t*>(mh) + sec->offset, sec->size };
                printf("segment %s sect %s => 0x%.8llx 0x%llx\n", sc->segname, sec->sectname, sec->addr, sec->size);
            }
        }
        else if (lc->cmd == LC_DYLD_INFO_ONLY)
        {
            dyld_info_command *dic = reinterpret_cast<dyld_info_command*>(p);
            dyld = reinterpret_cast<uint8_t*>(mh) + dic->lazy_bind_off;
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

#endif

uint8_t* CPatch::Rva(uint64_t rva) 
{
    auto v = sects.lower_bound(rva);
    if (sects.end() == v) return NULL;
    if (v->first != rva) --v;
    return const_cast<uint8_t*>(v->second.ptr) + 
        rva - v->second.rip;
}

CPatch::sec_ctx CPatch::Section(const char *name)
{
    for (auto it = sects.begin(); it != sects.end(); it++)
        if (strcmpi(name, it->second.name) == 0)
           return it->second;
    static sec_ctx zero = {};
    return zero;
}

uint64_t CPatch::Search(const char *name, const void *code, int s, int64_t off)
{
    sec_ctx sec = Section(name);
    for (uint32_t i = off; i < sec.size; ++i)
        if (memcmp(sec.ptr + i, code, s) == 0)
            return sec.rip + i;
    return 0;
}

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
