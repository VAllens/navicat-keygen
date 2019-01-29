#include "patch.h"
#include <vector>
#include <string.h>
#include <capstone/capstone.h>

#if defined(_WIN32)
#define strcmpi stricmp
#else
#define strcmpi strcasecmp
#endif

typedef struct 
{
    uint64_t rip;
    const uint8_t* ptr;
    size_t size;
    // patch
    const char* origin;
    uint8_t* replace;
    int length;
    uint8_t* patch;
} cs_ctx;

typedef std::vector<cs_ctx> cs_patch;

template<bool(*Match)(CPatch*, cs_insn*, cs_ctx&)>
int HandleJcc(CPatch *p, csh h, cs_ctx ctx, cs_ctx jumped);

template<bool(*Match)(CPatch*, cs_insn*, cs_ctx&)>
void FindPatch(CPatch *p, csh h, cs_ctx& ctx, cs_patch* patch = NULL)
{
    // Find patch offset
    cs_insn* insn = cs_malloc(h);
    cs_ctx prev = ctx;

    while (cs_disasm_iter(h, &ctx.ptr, &ctx.size, &ctx.rip, insn))
    {
        // if (patch) printf("%llx %s\t%s\n", insn->address, insn->mnemonic, insn->op_str);

        if (insn->mnemonic[0] == 'j')
        {
            cs_ctx jumped = {};
            jumped.rip = static_cast<uint64_t>(insn->detail->x86.operands[0].imm);
            jumped.ptr = p->Rva(jumped.rip);
            jumped.size = ctx.size - (jumped.ptr - ctx.ptr);
            jumped.origin = ctx.origin;
            if (!jumped.ptr) break;

            if (strcmpi(insn->mnemonic, "jmp") == 0)
            {
                ctx = jumped;
            }
            else if (HandleJcc<Match>(p, h, ctx, jumped) < 0)
            {
                ctx = jumped;
            }
        }
        else if (strcmpi(insn->mnemonic, "ret") == 0)
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

            printf("%llx %s\t%s, %.*s\n", insn->address, insn->mnemonic, insn->op_str, prev.length, prev.patch);

            // Judge string to patch is refer by other code
            if (prev.replace && p->Search(".text", insn->bytes, insn->size) > 1)
            {
                prev.patch = const_cast<uint8_t*>(prev.ptr) +
                    insn->detail->x86.encoding.imm_offset;
                prev.length = insn->detail->x86.encoding.imm_size;
            }
            else
            {
                prev.replace = NULL;
            }
            patch->push_back(prev);
            if (*ctx.origin == '\x00') break;
        }
        prev = ctx;
    }
    if (!insn) cs_free(insn, 1);
}

template<bool(*Match)(CPatch*, cs_insn*, cs_ctx&)>
int HandleJcc(CPatch *p, csh h, cs_ctx ctx, cs_ctx jumped)
{
    cs_insn* insn = cs_malloc(h);

    for (;;)
    {
        // process branch origin
        FindPatch<Match>(p, h, ctx);
        if (ctx.origin == NULL)
        {
            cs_free(insn, 1);
            return -1;
        }
        // process branch jumped
        FindPatch<Match>(p, h, jumped);
        if (jumped.origin == NULL)
        {
            cs_free(insn, 1);
            return 1;
        }
        // judge branch
        if (ctx.origin != jumped.origin)
        {
            cs_free(insn, 1);
            return ctx.origin > jumped.origin ? 1 : -1;
        }
    }
}

bool inline Printable(uint8_t *p, size_t s)
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

    if (strcmpi(insn->mnemonic, "mov") == 0) {
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

    if (strcmpi(insn->mnemonic, "push") != 0)
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

    uint8_t* data = p->Rva(insn->detail->x86.operands[0].imm);
    if (!data || *data == '\x00') return false;

    size_t len = 0;
    for (; data[len] != '\x00'; len++)
        if (!isprint(data[len]))
            return false;
    if (memcmp(data, ctx.origin, len) != 0)
        return true;

    ctx.replace = ctx.patch = data;
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

    if (strcmpi(insn->mnemonic, "mov") == 0)
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

    if (strcmpi(insn->mnemonic, "lea") != 0)
        return false;
    // as far as I know, all strings are loaded by "lea REG, QWORD PTR[RIP + disp]"
    // so it must be "[RIP + disp]"
    if (insn->detail->x86.operands[1].mem.base != X86_REG_RIP)
        return false;
    // scale must 1, otherwise pattern mismatches
    if (insn->detail->x86.operands[1].mem.scale != 1)
        return false;

    uint8_t* data = p->Rva(insn->address + insn->size +    // RIP
        insn->detail->x86.operands[1].mem.disp);
    if (!data || *data == '\x00') return false;

    size_t len = 0;
    for (; data[len] != '\x00'; len++)
        if (!isprint(data[len]))
            return false;
    // data must have at least one char
    // every char in PtrToString must be printable, otherwise pattern mismatches
    if (memcmp(data, ctx.origin, len) != 0)
        return true;

    ctx.replace = ctx.patch = data;
    ctx.length = len;
    return true;
}

// Brute-force search, str_s should be 1 or 2
/*static off_t SearchString(uint8_t* p, size_t s, const cs_ctx& ctx)
{
    size_t j;
    for (size_t i = 0; i < s; i++) {
        if (p[i] == ctx.origin[0]) {
            bool match = true;
            for (j = 1; j < ctx.replace[j] != '\x00'; j++) {
                if (p[i + j] != ctx.origin[j]) {
                    match = false;
                    break;
                }
            }
            if (match && p[i + j] == '\x00')
                return static_cast<off_t>(i);
        }    
    }
    return -1;
}*/

int CPatch::Patch3()
{
    // 48 8D 35 EF 74 E0 01
    std::string key = TrimKey(public_key);
    cs_ctx ctx = { 0, NULL, 0xcd03, key.c_str() };

#if defined(_WIN32)
    static const uint8_t code[] = {
        0x40, 0x55,                                         // push    rbp
        0x48, 0x8D, 0xAC, 0x24, 0x70, 0xBC, 0xFF, 0xFF,     // lea     rbp, [rsp-4390h]
        0xB8, 0x90, 0x44, 0x00, 0x00                        // mov     eax, 4490h
    };
    ctx.rip = FindCode(0x6b67424e, 0x250, code, sizeof(code));
#elif defined(__APPLE__)
    static const uint8_t code[] = {
        0x55,                 // push rbp
        0x48, 0x89, 0xE5,     // mov  rbp, rsp
        0x41, 0x57,           // push r15
        0x41, 0x56            // push r14
    };
    ctx.rip = FindCode(0x1e074ef, 0x250, code, sizeof(code));
#endif
    printf("find offset %llx\n", ctx.rip);
    if (!ctx.rip) return -2;

    ctx.ptr = Rva(ctx.rip);
    cs_patch patch;
    
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return -1;
    if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return -1;
    // Find patch offset
    FindPatch<CheckMatch_amd64>(this, h, ctx, &patch);
    if (!h) cs_close(&h);
    if (!ctx.origin || *ctx.origin) return -2;
    return 0;
}