#include "patch.h"
#include "helper.h"
#include <vector>

#include <capstone/capstone.h>

DECLARE_TRAIT(cs_insn, cs_free, 1);

#if defined(_WIN32)

typedef struct 
{
    uint64_t rip;
    const uint8_t* ptr;
    size_t size;
    // patch
    const char* origin;
    uint64_t vaddr;
    int length;
    uint8_t* patch;
} cs_ctx;

typedef std::vector<cs_ctx> cs_patch;
typedef bool (* CheckFunc)(CPatch*, cs_insn*, cs_ctx&);

template<bool(*Match)(CPatch*, cs_insn*, cs_ctx&)>
int HandleJcc(CPatch *p, csh h, cs_ctx ctx, cs_ctx jumped);

template<CheckFunc Match, CheckFunc Patch = nullptr>
void FindPatch(CPatch *p, csh h, cs_ctx& ctx, cs_patch* patch = NULL)
{
    // Find patch offset
    CAutoPtr<cs_insn> insn = cs_malloc(h);
    cs_ctx prev = ctx;

    while (cs_disasm_iter(h, &ctx.ptr, &ctx.size, &ctx.rip, insn))
    {
        // if (patch) printf("0x%.8llx %s\t%s\n", insn->address, insn->mnemonic, insn->op_str);

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
            // Judge string to patch is refer by other code
            if (prev.vaddr && Patch(p, insn, prev))
            {
                printf("0x%.8llx %s\t%s, %.*s, xref\n", insn->address, insn->mnemonic, insn->op_str, prev.length, prev.origin);
            }
            else
            {
                printf("0x%.8llx %s\t%s, %.*s\n", insn->address, insn->mnemonic, insn->op_str, prev.length, prev.origin);
            }
            if (*ctx.origin == '\0') break;
        }
        prev = ctx;
    }
}

template<CheckFunc Match>
int HandleJcc(CPatch *p, csh h, cs_ctx ctx, cs_ctx jumped)
{
    CAutoPtr<cs_insn> insn = cs_malloc(h);

    do {
        // process branch origin
        FindPatch<Match>(p, h, ctx);
        if (ctx.origin == NULL) break;
        // process branch jumped
        FindPatch<Match>(p, h, jumped);
        if (jumped.origin == NULL) break;
        // judge branch
    } while (ctx.origin == jumped.origin);

    return ctx.origin > jumped.origin ? 1 : -1;
}

bool inline Printable(uint8_t *p, size_t s)
{
    for (size_t i = 0; i < s; ++i)
        if (!isprint(p[i]))
            return false;
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

    ctx.vaddr = insn->address + insn->size +    // RIP
        insn->detail->x86.operands[1].mem.disp;
    uint8_t* data = p->Rva(ctx.vaddr);
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
    auto sec = p->Section(sect_code);
    uint8_t off = insn->detail->x86.encoding.disp_offset;
    int n = 0;
    for (size_t i = 0; i < sec.size - insn->size; ++i)
    {
        if (memcmp(sec.ptr + i, insn->bytes, off) == 0)
        {
            uint32_t disp = *(uint32_t*)(sec.ptr + i + off);
            if (sec.rip + i + insn->size + disp == ctx.vaddr && ++n > 1)
            {
                ctx.patch = const_cast<uint8_t*>(ctx.ptr) + 
                    insn->detail->x86.encoding.disp_offset;
                ctx.length = insn->detail->x86.encoding.disp_size;
                return true;
            }
        }
    }
    ctx.vaddr = 0;
    return false;   
}

int CPatch::Patch3()
{
    std::string key = TrimKey(public_key.c_str());
    cs_ctx ctx = { 0, NULL, 0xcd03, key.c_str() };
    static const uint8_t code[] = {
        0x40, 0x55,                                         // push    rbp
        0x48, 0x8D, 0xAC, 0x24, 0x70, 0xBC, 0xFF, 0xFF,     // lea     rbp, [rsp-4390h]
        0xB8, 0x90, 0x44, 0x00, 0x00                        // mov     eax, 4490h
    };
    ctx.rip = Search(sect_code, code, sizeof(code));
    printf("find offset 0x%.8llx\n", ctx.rip);
    if (!ctx.rip) return -2;

    ctx.ptr = Rva(ctx.rip);
    cs_patch patch;
    
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return -1;
    if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return -1;
    // Find patch offset
    FindPatch<CheckMatch_amd64, CheckPatch_amd64>(this, h, ctx, &patch);
    if (!h) cs_close(&h);
    if (!ctx.origin || *ctx.origin) return -2;
    return 0;
}

#elif defined(__APPLE__)

#include <keystone/keystone.h>
#include <mach-o/loader.h>

DECLARE_TRAIT(ks_engine, ks_close);

const char * ResolvedTo(CPatch *p, csh h, uint64_t rip) 
{
    CAutoPtr<cs_insn> insn = cs_malloc(h);
    size_t size = 10;
    const uint8_t *code = p->Rva(rip);
    if (!code) return NULL;

    if (!cs_disasm_iter(h, &code, &size, &rip, insn))
        return NULL;
    //
    // A stub helper proc must look like:
    //     push xxxxxx; (xxxxx is a imm value)
    //     jmp loc_xxxxx
    //
    if (strcasecmp(insn->mnemonic, "push") != 0 || insn->detail->x86.operands[0].type != X86_OP_IMM)
        return NULL;

    code = p->dyld + insn->detail->x86.operands[0].imm;
    while ((*code & BIND_OPCODE_MASK) != BIND_OPCODE_DONE) {
        switch (*code & BIND_OPCODE_MASK) {
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:         // 0x10
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:         // 0x30
            case BIND_OPCODE_SET_TYPE_IMM:                  // 0x50
            case BIND_OPCODE_DO_BIND:                       // 0x90
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:   // 0xB0
                ++code;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:        // 0x20
            case BIND_OPCODE_SET_ADDEND_SLEB:               // 0x60
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:   // 0x70
            case BIND_OPCODE_ADD_ADDR_ULEB:                 // 0x80
            case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:         // 0xA0
                while(*(++code) & 0x80);
                ++code;
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: // 0x40
                return reinterpret_cast<const char*>(code + 1);
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:  // 0xC0
                //
                // This opcode is too rare to appear,
                // It is okay to dismiss this opcode
                //
                return NULL;
            default:
                return NULL;
        }
    }
    return NULL;
}

const char patch3magic[] =
    "BIjWyoeRR0NBgkqnDZWxCgKCEAw1dqF3DTvOB91ZHwecJYFrdM1KEh"
    "1yVeRoGqSdLLGZGUlngig3OD5mMzs889IqWqqfHSeHMvzyg1p6UPCY"
    "nesxa9M2dDUrXHomRHOFHSfsbSXRFwt5GivtnJG9lLJHZ7XWeIQABi"
    "dKionYD3O6c9tvUAoDosUJAdQ1RaSXTzyETbHTRtnTPeLpO3EedGMs"
    "v3jG9yPcmmdYkddSeJRwn2raPJmnvdHScHUACw0sUNuosAqPaQbTQN"
    "PATDzcrnd1Sf8RIbUp4MQJFVJugPLVZbP53Gjtyyniqe5q75kva8Qm"
    "Hr1uOuXkVppe3cwECaGamupG43L1XfcpRjCMrxRep3s2VlbL01xmfz"
    "5cIhrj34iVmgZSAmIb8ZxiHPdp1oDMFkbNetZyWegqjAHQQ9eoSOTD"
    "bERbKEwZ5FLeLsbNAxfqsapB1XBvCavFHualx6bxVxuRQceh4z8kaZ"
    "iv2pOKbZQSJ2Dx5HEq0bYZ6y6b7sN9IaeDFNQwjzQn1K7k3XlYAPWC"
    "IvDe8Ln0FUe4yMNmuUhu5RTjxE05hUqtz1HjJvYQ9Es1VA6LflKQ87"
    "TwIXBNvfrcHaZ72QM4dQtDUyEMrLgMDkJBDM9wqIDps65gSlAz6eHD"
    "8tYWUttrWose0cH0yykVnqFzPtdRiZyZRfio6lGyK48mIC9z7T6MN3"
    "a7OaLZHZSwzcpQLcGi7M9q1wXLq4Ms1UvlwntB9FLHc63tHPpG8rhn"
    "XhZIk4QrSm4GYuEKQVHwku6ulw6wfggVL8FZPhoPCGsrb2rQGurBUL"
    "3lkVJ6RO9VGHcczDYomXqAJqlt4y9pkQIj9kgwTrxTzEZgMGdYZqsV"
    "4Bd5JjtrL7u3LA0N2Hq9Xvmmis2jDVhSQoUoGukNIoqng3SBsf0E7b"
    "4W0S1aZSSOJ90nQHQkQShE9YIMDBbNwIg2ncthwADYqibYUgIvJcK9"
    "89XHnYmZsdMWtt53lICsXE1vztR5WrQjSw4WXDiB31LXTrvudCB6vw"
    "kCQa4leutETpKLJ2bYaOYBdoiBFOwvf36YaSuRoY4SP2x1pWOwGFTg"
    "d90J2uYyCqUa3Q3iX52iigT4EKL2vJKdJ";

int CPatch::Patch3()
{
    static const uint8_t code[] = {
        0x55,                 // push rbp
        0x48, 0x89, 0xE5,     // mov  rbp, rsp
        0x41, 0x57,           // push r15
        0x41, 0x56,           // push r14
        0x53                  // push rbx
    };
    uint64_t func_rva = Search(sect_code, code, sizeof(code));
    printf("find offset 0x%.8llx\n", func_rva);
    if (!func_rva) return -2;

    uint64_t key_rva = Search("__const", patch3magic, sizeof(patch3magic));
    if (!key_rva) return -3;

    sec_ctx stub = Section("__stubs");
    {
        csh h = 0;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return -1;
        if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return -1;

        // Find patch offset
        CAutoPtr<cs_insn> insn = cs_malloc(h);
        while (cs_disasm_iter(h, &stub.ptr, &stub.size, &stub.rip, insn))
        {
            //
            // As far as I know, all stub functions have a pattern looking like:
            //     jmp qword ptr [RIP + xxxx]
            //
            if (strcasecmp(insn->mnemonic, "jmp") == 0 && insn->detail->x86.operands[0].type == X86_OP_MEM && insn->detail->x86.operands[0].mem.base == X86_REG_RIP) 
            {
                uint8_t *la_symbol = Rva(stub.rip + insn->detail->x86.operands[0].mem.disp);
                if (!la_symbol) continue;

                const char *stub_ptr = ResolvedTo(this, h, *reinterpret_cast<uint64_t*>(la_symbol));
                if (!stub_ptr) continue;
                //
                // __ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc
                //     is the mangled name of "std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::append(char const*)",
                //     which is, as known as, "std::string::append(const char*)"
                // You can demangle it by c++flit
                // e.g.
                //     c++filt -_ '__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc'
                //
                if (strcasecmp(stub_ptr, "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc") == 0)
                {
                    printf("0x%.8llx stub %s\n", stub.rip, stub_ptr);
                    break;
                }
            }
        }
        if (!h) cs_close(&h);
    }

    char asm_code[512] = {};
    sprintf(asm_code,
        "push rbp;"
        "mov rbp, rsp;"
        "push r15;"
        "push r14;"
        "push rbx;"
        "sub rsp, 0x48;"

        "mov rbx, rdi;"

        "xor rax, rax;"
        "mov qword ptr[rsp], rax;"
        "mov qword ptr[rsp + 0x8], rax;"
        "mov qword ptr[rsp + 0x10], rax;"

        "lea rdi, qword ptr[rsp];"
        "lea rsi, qword ptr[0x%016llx];"  // filled with address to Keyword
        "call 0x%016llx;"                 // filled with address to std::string::append(const char*)

        "mov rax, qword ptr[rsp];"
        "mov qword ptr[rbx], rax;"
        "mov rax, qword ptr[rsp + 0x8];"
        "mov qword ptr[rbx + 0x8], rax;"
        "mov rax, qword ptr[rsp + 0x10];"
        "mov qword ptr[rbx + 0x10], rax;"

        "mov rax, rbx;"
        "add rsp, 0x48;"
        "pop rbx;"
        "pop r14;"
        "pop r15;"
        "pop rbp;"
        "ret;",
        key_rva,
        stub.rip);


/*
    {
        uint8_t* op_codes = NULL;
        size_t op_size = 0, count = 0;
        CAutoPtr<ks_engine> ks = NULL;
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK) return -5;
        if (ks_asm(ks, asm_code, func_rva, &op_codes, &op_size, &count) != KS_ERR_OK) return -5;
        // patch shell code
        // memcpy(Rva(func_rva), op_codes, op_size);
        // patch public key

        ks_free(op_codes);
    }
*/

    return 0;
}

#endif