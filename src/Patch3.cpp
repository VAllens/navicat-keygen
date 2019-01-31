#include "StdAfx.h"
#include "Patch.h"
#include "Helper.h"

#include <capstone/capstone.h>
#pragma comment(lib, "capstone.lib") 

DECLARE_TRAIT(cs_insn, cs_free, 1);

typedef struct
{
    uint64_t rip;
    const uint8_t* ptr; // addr of code
    size_t size;
    // patch
    const char* origin; // public string keyword
    uint64_t vaddr; // virtual addr of keyword
    size_t length; // length of patch
    uint8_t* patch; // pointer to patch
} cs_ctx;

typedef CAtlArray<cs_ctx> cs_patch;
typedef bool(*CheckFunc)(CPatch*, cs_insn*, cs_ctx&);

template<CheckFunc Match, CheckFunc Patch = NULL>
void FindPatch(CPatch *p, csh h, cs_ctx& ctx, cs_patch* patch = NULL)
{
    // Find patch offset
    CHelpPtr<cs_insn> insn = cs_malloc(h);
    cs_ctx prev = ctx;

    while (cs_disasm_iter(h, &ctx.ptr, &ctx.size, &ctx.rip, insn))
    {
        // if (Patch) ATLTRACE(TEXT("%p %hs, %hs\n"), uint32_t(insn->address), insn->mnemonic, insn->op_str);
        if (insn->mnemonic[0] == 'j')
        {
            cs_ctx jumped = { insn->detail->x86.operands[0].imm };
            jumped.ptr = p->RVA(jumped.rip);
            jumped.size = ctx.size - (jumped.ptr - ctx.ptr);
            jumped.origin = ctx.origin;
            if (!jumped.ptr) break;

            if (_stricmp(insn->mnemonic, "jmp") == 0)
            {
                ctx = jumped;
            }
            else if (HandleJcc<Match>(p, h, ctx, jumped) < 0)
            {
                ctx = jumped;
            }
        }
        else if (_stricmp(insn->mnemonic, "ret") == 0)
        {
            ctx.origin = NULL; // find failed
            break;
        }
        else if (Match(p, insn, prev))
        {
            if (prev.patch == NULL)
            {
                ctx.origin = NULL; // find failed
                break;
            }
            ctx.origin += prev.length;
            if (!patch) break;
            // Judge string to patch is refer by other code
            if (prev.vaddr && Patch(p, insn, prev))
                ATLTRACE(TEXT("%p %hs, %hs, %.*hs, xref\n"), uint32_t(insn->address), insn->mnemonic, insn->op_str, prev.length, prev.origin);
            else
                ATLTRACE(TEXT("%p %hs, %hs, %.*hs\n"), uint32_t(insn->address), insn->mnemonic, insn->op_str, prev.length, prev.origin);
            patch->Add(prev);
            if (*ctx.origin == '\0') break;
        }
        prev = ctx;
    }
}

template<CheckFunc Match>
int HandleJcc(CPatch *p, csh h, cs_ctx ctx, cs_ctx jumped)
{
    CHelpPtr<cs_insn> insn = cs_malloc(h);
    do {
        // process branch origin
        FindPatch<Match>(p, h, ctx);
        if (ctx.origin == NULL) break;
        // process branch jumped
        FindPatch<Match>(p, h, jumped);
        if (jumped.origin == NULL) break;
        // judge branch
    } while (ctx.origin != jumped.origin);

    return ctx.origin > jumped.origin ? 1 : -1;
}

bool inline Printable(PBYTE p, size_t s)
{
    for (size_t i = 0; i < s; ++i)
        if (!isprint(p[i]))
            return false;
    return true;
}

bool CheckMatch_x86(CPatch *p, cs_insn* insn, cs_ctx& ctx)
{
    // the instruction we're interested in has one of the following patterns:
    //  1. mov PTR [MEM], IMM   (IMM must consist of printable chars)
    //     except pattern "mov [ebp - 0x4], IMM"
    //  2. push IMM             (IMM must consist of printable chars)
    //  3. push offset MEM      (MEM must point to a non-empty printable string)                    
    //
    if (insn->detail->x86.op_count < 1)
        return false;

    if (_stricmp(insn->mnemonic, "mov") == 0) {
        // filter the case "mov [ebp - 0x4], IMM"
        // because IMM may consist of printable chars in that case, which can mislead us.
        //
        // Here I use "> -0x30" to intensify condition, instead of "== -0x4"
        if (insn->detail->x86.operands[0].type == X86_OP_MEM &&
            insn->detail->x86.operands[0].mem.base == X86_REG_EBP &&
            insn->detail->x86.operands[0].mem.disp > -0x30)
            return false;

        if (insn->detail->x86.operands[1].type != X86_OP_IMM)
            return false;

        // each bytes of ImmValue must be printable;
        uint8_t off = insn->detail->x86.encoding.imm_size;
        if (!Printable(insn->bytes + insn->detail->x86.encoding.imm_offset, off))
            return false;

        if (memcmp(&insn->detail->x86.operands[1].imm, ctx.origin, off))
            return true;
        ctx.patch = const_cast<uint8_t*>(ctx.ptr) + insn->detail->x86.encoding.imm_offset;
        ctx.length = off;
        return true;
    }

    if (_stricmp(insn->mnemonic, "push") != 0)
        return false;

    if (insn->detail->x86.operands[0].type != X86_OP_IMM)
        return false;
    // test if match pattern 2
    uint8_t off = insn->detail->x86.encoding.imm_size;
    if (Printable(insn->bytes + insn->detail->x86.encoding.imm_offset, off))
    {
        if (memcmp(&insn->detail->x86.operands[0].imm, ctx.origin, off))
            return true;
        ctx.patch = const_cast<uint8_t*>(ctx.ptr) + insn->detail->x86.encoding.imm_offset;
        ctx.length = off;
        return true;
    }

    ctx.vaddr = insn->detail->x86.operands[0].imm - p->pINH->OptionalHeader.ImageBase;
    uint8_t* data = p->RVA(ctx.vaddr);
    if (!data || *data == '\0') return false;

    size_t len = 0;
    for (; data[len] != '\0'; len++)
        if (!isprint(data[len]))
            return false;
    if (memcmp(data, ctx.origin, len) != 0)
        return true;

    ctx.patch = data;
    ctx.length = len;
    return true;
}

bool CheckMatch_amd64(CPatch *p, cs_insn* insn, cs_ctx& ctx)
{
    // the instruction we're interested in has one of the following patterns:
    //  1. mov PTR [MEM], IMM   (IMM must consist of printable chars)               // for IMM_DATA
    //  2. lea REG, PTR [MEM]   (MEM must point to a non-empty printable string)    // for STRING_DATA
    if (insn->detail->x86.op_count != 2)
        return false;

    if (_stricmp(insn->mnemonic, "mov") == 0)
    {
        if (insn->detail->x86.operands[1].type != X86_OP_IMM)
            return false;

        uint8_t off = insn->detail->x86.encoding.imm_size;
        if (!Printable(insn->bytes + insn->detail->x86.encoding.imm_offset, off))
            return false;

        if (memcmp(&insn->detail->x86.operands[1].imm, ctx.origin, off))
            return true;
        ctx.patch = const_cast<uint8_t*>(ctx.ptr) + insn->detail->x86.encoding.imm_offset;
        ctx.length = off;
        return true;
    }

    if (_stricmp(insn->mnemonic, "lea") != 0)
        return false;
    // as far as I know, all strings are loaded by "lea REG, QWORD PTR[RIP + disp]"
    // so it must be "[RIP + disp]"
    if (insn->detail->x86.operands[1].mem.base != X86_REG_RIP)
        return false;
    // scale must 1, otherwise pattern mismatches
    if (insn->detail->x86.operands[1].mem.scale != 1)
        return false;

    ctx.vaddr = insn->address + insn->size +    // RIP
        insn->detail->x86.operands[1].mem.disp;
    uint8_t* data = p->RVA(ctx.vaddr);
    if (!data || *data == '\0') return false;

    size_t len = 0;
    for (; data[len] != '\0'; len++)
        if (!isprint(data[len]))
            return false;
    // data must have at least one char
    // every char in PtrToString must be printable, otherwise pattern mismatches
    if (memcmp(data, ctx.origin, len) != 0)
        return true;

    ctx.patch = data;
    ctx.length = len;
    return true;
}


bool CheckPatch_amd64(CPatch *p, cs_insn* insn, cs_ctx& ctx)
{
    PIMAGE_SECTION_HEADER h = p->Section(".text");
    PBYTE raw = p->pView + h->PointerToRawData;
    DWORD offset = insn->detail->x86.encoding.disp_offset;
    int n = 0;
    for (DWORD i = 0; i < h->SizeOfRawData - insn->size; ++i)
    {
        if (memcmp(raw + i, insn->bytes, offset) == 0)
        {
            DWORD disp = *(PDWORD)(raw + i + offset);
            if (h->VirtualAddress + i + insn->size + disp == ctx.vaddr && ++n > 1)
            {
                ctx.patch = const_cast<uint8_t*>(ctx.ptr) + insn->detail->x86.encoding.disp_offset;
                ctx.length = insn->detail->x86.encoding.disp_size;
                return true;
            }
        }
    }
    ctx.vaddr = 0;
    return false;
}

bool CheckPatch_x86(CPatch *p, cs_insn* insn, cs_ctx& ctx)
{
    PIMAGE_SECTION_HEADER h = p->Section(".text");
    PBYTE raw = p->pView + h->PointerToRawData;
    int n = 0;
    for (DWORD i = 0; i < h->SizeOfRawData - insn->size; ++i)
    {
        if (memcmp(raw + i, insn->bytes, insn->size) == 0 && ++n > 1)
        {
            ctx.patch = const_cast<uint8_t*>(ctx.ptr) + insn->detail->x86.encoding.imm_offset;
            ctx.length = insn->detail->x86.encoding.imm_size;
            return true;
        }
    }
    ctx.vaddr = 0;
    return false;
}

// Brute-force search, str_s should be 1 or 2
static off_t SearchString(uint8_t* p, size_t s, const cs_ctx& ctx)
{
    size_t j;
    for (size_t i = 0; i < s; i++) {
        if (p[i] == ctx.origin[0]) {
            bool match = true;
            for (j = 1; p[j] != '\0'; j++) {
                if (p[i + j] != ctx.origin[j]) {
                    match = false;
                    break;
                }
            }
            if (match && p[i + j] == '\0')
                return static_cast<off_t>(i);
        }
    }
    return -1;
}

HRESULT CPatch::Patch3(LPCSTR pData, int nLen)
{
    PIMAGE_SECTION_HEADER pRdata = Section(".rdata"), pText = Section(".text");
    if (!pRdata || !pText) return ERROR_BAD_EXE_FORMAT;

    CHeapPtr<CHAR> pKey;
    PBYTE pRawText = pView + pText->PointerToRawData;
    PIMAGE_DATA_DIRECTORY pRva = NULL;
    cs_patch pPatch;

    pKey.Allocate(nLen);
    TrimKey(pPublic, pKey, nLen);

    if (pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        static const BYTE pCode[] = {
            0x40, 0x55,                                         // push    rbp
            0x48, 0x8D, 0xAC, 0x24, 0x70, 0xBC, 0xFF, 0xFF,     // lea     rbp, [rsp-4390h]
            0xB8, 0x90, 0x44, 0x00, 0x00                        // mov     eax, 4490h
        };
        DWORD uCode = 0;
        for (DWORD i = 0; i < pText->SizeOfRawData; ++i)
        {
            if (*(PUINT32)(pRawText + i) == 0x6b67424e)
            {
                for (DWORD j = i - 0x250; j < i; ++j)
                {
                    if (memcmp(pRawText + j, pCode, sizeof(pCode)) == 0)
                    {
                        uCode = j;
                        break;
                    }
                }
            }
        }
        if (!uCode) return ERROR_NOT_FOUND;

        csh h;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return E_FAIL;
        if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return E_FAIL;
        // Find patch offset
        cs_ctx ctx = { pText->VirtualAddress + uCode, pRawText + uCode, 0xcd03, pKey };
        FindPatch<CheckMatch_amd64, CheckPatch_amd64>(this, h, ctx, &pPatch);
        if (!h) cs_close(&h);
        if (!ctx.origin || *ctx.origin) return ERROR_NOT_FOUND;

        pRva = reinterpret_cast<PIMAGE_NT_HEADERS64>(pINH)
            ->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC;
    }
    else if (pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        static const BYTE pCode[] = {
            0x55,           // push    ebp
            0x8B, 0xEC,     // mov     ebp, esp
            0x6A, 0xFF      // push    0xffffffff
        };
        DWORD uCode = 0;
        for (DWORD i = 0; i < pText->SizeOfRawData; ++i)
        {
            if (*(PUINT32)(pRawText + i) == 0x6b67424e)
            {
                for (DWORD j = i - 0x1B0; j < i; ++j)
                {
                    if (memcmp(pRawText + j, pCode, sizeof(pCode)) == 0)
                    {
                        uCode = j;
                        break;
                    }
                }
            }
        }
        if (!uCode) return ERROR_NOT_FOUND;

        csh h;
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &h) != CS_ERR_OK) return E_FAIL;
        if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return E_FAIL;
        // Find patch offset
        cs_ctx ctx = { pText->VirtualAddress + uCode, pRawText + uCode, 0x9014, pKey };
        FindPatch<CheckMatch_x86, CheckPatch_x86>(this, h, ctx, &pPatch);
        if (!h) cs_close(&h);
        if (!ctx.origin || *ctx.origin) return ERROR_NOT_FOUND;

        pRva = reinterpret_cast<PIMAGE_NT_HEADERS32>(pINH)
            ->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC;
    }
    else
    {
        return E_NOTIMPL;
    }

    // begin patch
    TrimKey(pData, pKey, nLen);

    CReloc mapReloc(reinterpret_cast<PIMAGE_BASE_RELOCATION>(RVA(pRva->VirtualAddress)));
    PBYTE pRawData = pView + pRdata->PointerToRawData;
    for (size_t i = 0; i < pPatch.GetCount(); i++)
    {
        if (pPatch[i].vaddr)
        {
            uint32_t offset = static_cast<uint32_t>(pPatch[i].vaddr) - pRdata->VirtualAddress;
            do {
                off_t off = SearchString(pRawData + offset, pRdata->SizeOfRawData - offset, pPatch[i]);
                if (off < 0) return ERROR_INVALID_DATA;
                if ((offset += off) > pRdata->SizeOfRawData) return ERROR_INVALID_DATA;

            } while (mapReloc.IsReloc(pRdata->VirtualAddress + offset++, pPatch[i].length + 1));

            uint64_t disp = 0;
            memcpy(&disp, pPatch[i].patch, pPatch[i].length);
            disp += pRdata->VirtualAddress + offset - 1 - pPatch[i].vaddr;
            memcpy(pPatch[i].patch, &disp, pPatch[i].length);
        }
        else
        {
            memcpy(pPatch[i].patch, pPatch[i].origin, pPatch[i].length);
        }
    }
    return S_OK;
}