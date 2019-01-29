#include "StdAfx.h"
#include "Patch.h"

CReloc::CReloc(PIMAGE_BASE_RELOCATION pIBR)
{
    while (pIBR->VirtualAddress)
    {
        PWORD pReloc = reinterpret_cast<PWORD>(pIBR + 1);
        DWORD uReloc = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (DWORD i = 0; i < uReloc; ++i)
        {
            switch (pReloc[i] >> 12) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGH:
            case IMAGE_REL_BASED_LOW:
            case IMAGE_REL_BASED_HIGHADJ:
                this->SetAt(pIBR->VirtualAddress + (pReloc[i] & 0x0fff), 2);
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                this->SetAt(pIBR->VirtualAddress + (pReloc[i] & 0x0fff), 4);
                break;
#if defined(IMAGE_REL_BASED_DIR64)
            case IMAGE_REL_BASED_DIR64:
                this->SetAt(pIBR->VirtualAddress + (pReloc[i] & 0x0fff), 8);
                break;
#endif
            }
        }
        pIBR = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pReloc + uReloc);
    }
}

bool CReloc::IsReloc(DWORD uRva, DWORD cbRva)
{
    POSITION pos = this->FindFirstKeyAfter(uRva);
    if (!pos) return false;

    DWORD found = this->GetKeyAt(pos);
    if (found == uRva)
        return true;

    if (found <= uRva && uRva < found + this->GetValueAt(pos))
        return true;

    if (uRva + cbRva <= this->GetPrev(pos)->m_key)
        return false;

    return true;
}