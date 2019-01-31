#include "StdAfx.h"
#include "Patch.h"

#include <openssl/sha.h>
#include <openssl/blowfish.h>

void BCrypt(LPCSTR in, PBYTE out, size_t len)
{
    SHA_CTX ctx;
    BYTE digest[SHA_DIGEST_LENGTH];
    const char chipher[] = { '2', '3', '9', '7', '0', '7', '9', '0' };

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, chipher, sizeof(chipher));
    SHA1_Final(digest, &ctx);

    BF_KEY key;
    BYTE cv[BF_BLOCK] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    BF_set_key(&key, sizeof(digest), digest);
    BF_ecb_encrypt(cv, cv, &key, BF_ENCRYPT);

    for (size_t i = 0; i < len; i += BF_BLOCK)
    {
        if (i + BF_BLOCK < len)
        {
            *((PDWORD64)(out + i)) = *((PDWORD64)cv) ^ *((PDWORD64)(in + i));
            BF_ecb_encrypt(out + i, out + i, &key, BF_ENCRYPT);
            *((PDWORD64)cv) ^= *((PDWORD64)(out + i));
        }
        else
        {
            BF_ecb_encrypt(cv, cv, &key, BF_ENCRYPT);
            for (size_t j = i; j < len; j++) *(out + j) = *(in + j) ^ cv[j - i];
        }
    }
}

bool CheckKey1(LPCSTR pKey, int nLen)
{
    for (int i = 0; i < nLen; i++)
        if (!isdigit(pKey[i]))
            return false;
    return true;
}

HRESULT CPatch::Patch1(LPCSTR pData, int nLen)
{
    PIMAGE_SECTION_HEADER pRdata = Section(".rdata"), pText = Section(".text");
    if (!pRdata || !pText) return ERROR_BAD_EXE_FORMAT;
    // cal patch magic
    CHeapPtr<BYTE> pBin;
    CAtlStringA pHex;
    int nKey = static_cast<int>(strlen(pPublic));
    int nHex = AtlHexEncodeGetRequiredLength(nKey);
    PSTR szHex = pHex.GetBufferSetLength(nHex);

    pBin.AllocateBytes(nKey);
    BCrypt(pPublic, pBin, nKey);
    AtlHexEncode(pBin, nKey, szHex, &nHex);

    // split encrypted_pem_pubkey to 5 part:    |160 chars|8 chars|742 chars|5 chars|5 chars|
    //                                                         |                |
    //                                                        imm1             imm3
    struct {
        int nLen;
        ULONG uImm;
        LPCSTR pOrigin;
        PBYTE pPatch;
    } pPatch[] = { { 160 }, { 8 }, { 742 }, { 5 }, { 5 } };
    
    for (int i = 0, n = 0; i < _countof(pPatch); i++)
    {
        pPatch[i].pOrigin = szHex + n;
        if (i % 2 == 0)
        {
            PBYTE pRawRdata = pView + pRdata->PointerToRawData;
            for (DWORD j = 0; j < pRdata->SizeOfRawData; ++j)
            {
                if (memcmp(pRawRdata + j, pPatch[i].pOrigin, pPatch[i].nLen) == 0)
                {
                    pPatch[i].pPatch = pRawRdata + j;
                    break;
                }
            }
            if (!pPatch[i].pPatch) return ERROR_NOT_FOUND;
        }
        else
        {
            pPatch[i].uImm = strtoul(pHex.Mid(n, pPatch[i].nLen), NULL, 10);
        }
        n += pPatch[i].nLen;
    }
    {
        PBYTE pRawText = pView + pText->PointerToRawData;
        for (DWORD j = 0; j < pText->SizeOfRawData; ++j)
        {
            if (memcmp(pRawText + j, &pPatch[1].uImm, 4) == 0)
            {
                for (DWORD i = j - 64; i < j + 64; i++)
                {
                    if (memcmp(pRawText + i, &pPatch[3].uImm, 4) == 0)
                    {
                        pPatch[1].pPatch = pRawText + j;
                        pPatch[3].pPatch = pRawText + i;
                        break;
                    }
                }
            }
        }
        if (!pPatch[1].pPatch || !pPatch[3].pPatch) return ERROR_NOT_FOUND;
    }

    // Make patch
    memcpy(szHex, pData, nLen);
    memset(szHex + nLen, 0, nKey - nLen);
    BCrypt(szHex, pBin, nKey);
    nHex = AtlHexEncodeGetRequiredLength(nKey);
    AtlHexEncode(pBin, nKey, szHex, &nHex);

    if (!CheckKey1(pPatch[1].pOrigin, pPatch[1].nLen) ||
        !CheckKey1(pPatch[3].pOrigin, pPatch[3].nLen))
        return ERROR_INVALID_DATA;

    for (int i = 0, n = 0; i < _countof(pPatch); i++)
    {
        if (i % 2 == 0)
        {
            memcpy(pPatch[i].pPatch, pPatch[i].pOrigin, pPatch[i].nLen);
        }
        else
        {
            UINT32 imm = strtoul(pHex.Mid(n, pPatch[i].nLen), NULL, 10);
            memcpy(pPatch[i].pPatch, &imm, sizeof(imm));
        }
        n += pPatch[i].nLen;
    }
    return S_OK;
}