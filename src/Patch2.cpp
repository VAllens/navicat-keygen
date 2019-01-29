#include "StdAfx.h"
#include "Patch.h"

HRESULT CPatch::Patch2(LPCSTR pData, int nLen)
{
    PIMAGE_SECTION_HEADER pText = Section(".text");
    if (!pText) return ERROR_BAD_EXE_FORMAT;

    CHeapPtr<CHAR> pKey;
    pKey.Allocate(nLen);
    int nKey = TrimKey(pPublic, pKey, nLen);

    CAtlArray<PBYTE> pPatch;
    pPatch.SetCount(nKey);

    if (pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
    {
        PBYTE pRawText = pView + pText->PointerToRawData;
        BYTE pCode[5] = { 0x83, // asm('xor eax, public_key[i]')
            0xf0, 0x4d, 0x88, 0x05 };// asm_prefix('mov byte ptr ds:xxxxxxxxxxxxxxxx, al')
        DWORD j = 0;
        for (int i = 0; i < nKey; i++)
        {
            pCode[2] = pKey[i];
            for (; j < pText->SizeOfRawData; ++j)
            {
                if (memcmp(pRawText + j, pCode, sizeof(pCode)) == 0)
                {
                    pPatch[i] = pRawText + j++;
                    break;
                }
            }
            if (!pPatch[i]) return ERROR_NOT_FOUND;
        }
    }
    else if (pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        PBYTE pRawText = pView + pText->PointerToRawData;
        BYTE pCode[5] = { };
        DWORD j = 0, n = 0;
        for (int i = 0; i < nKey; i++)
        {
            switch (i % 3)
            {
            case 0:
                pCode[0] = 0x83;      // pCode = asm('xor edx, public_key[i]') + 
                pCode[1] = 0xf2;
                pCode[2] = pKey[i];
                pCode[3] = 0x88;      //               asm_prefix('mov byte ptr ds:xxxxxxxx, dl')
                pCode[4] = 0x15;
                n = 5;
                break;
            case 1:
                pCode[0] = 0x83;      // pCode = asm('xor eax, public_key[i]') + 
                pCode[1] = 0xf0;
                pCode[2] = pKey[i];
                pCode[3] = 0xa2;      //               asm_prefix('mov byte ptr ds:xxxxxxxx, al')
                n = 4;
                break;
            default:
                pCode[0] = 0x83;      // public_key[i] = asm('xor ecx, public_key[i]') + 
                pCode[1] = 0xf1;
                pCode[2] = pKey[i];
                pCode[3] = 0x88;      //               asm_prefix('mov byte ptr ds:xxxxxxxx, cl')
                pCode[4] = 0x0D;
                n = 5;
            }
            for (; j < pText->SizeOfRawData; ++j)
            {
                if (memcmp(pRawText + j, pCode, n) == 0)
                {
                    pPatch[i] = pRawText + j++;
                    break;
                }
            }
            if (!pPatch[i]) return ERROR_NOT_FOUND;
        }
    }
    else
    {
        return E_NOTIMPL;
    }

    if (pPatch[nKey - 1] - pPatch[0] > 0x100000) return ERROR_NOT_FOUND;
    // make patch
    TrimKey(pData, pKey, nLen);
    for (int i = 0; i < nKey; i++)
    {
        ATLTRACE("offset %c => %c : %p\n", pPatch[i][2], pKey[i], pPatch[i]);
        pPatch[i][2] = pKey[i];
    }
    return S_OK;
}