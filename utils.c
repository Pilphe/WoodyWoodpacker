#include "woody.h"

DWORD AlignDword(DWORD dwToAlign, DWORD dwAlignment)
{
    return ((dwToAlign + (dwAlignment - 1)) & ~(dwAlignment - 1));
}

PIMAGE_NT_HEADERS64 GetNtHeaders(PVOID pMappedFile)
{
    return ((PIMAGE_NT_HEADERS64)((PBYTE)(pMappedFile)+((PIMAGE_DOS_HEADER)(pMappedFile))->e_lfanew));
}

PIMAGE_SECTION_HEADER GetSectionTable(PIMAGE_NT_HEADERS64 pNtHeaders)
{
    return ((PIMAGE_SECTION_HEADER)((PBYTE)(pNtHeaders)+sizeof(IMAGE_NT_HEADERS64)));
}

PIMAGE_SECTION_HEADER GetNewSectionHeader(PIMAGE_NT_HEADERS64 pNtHeaders)
{
    return ((PIMAGE_SECTION_HEADER)(GetSectionTable(pNtHeaders) + pNtHeaders->FileHeader.NumberOfSections));
}

PIMAGE_SECTION_HEADER GetSectionHeaderFromRva(PWOODY pWoody, DWORD dwRva)
{
    PIMAGE_SECTION_HEADER pSectionHeader;
    WORD wNumberOfSections;

    pSectionHeader = pWoody->pSectionHeaders;
    wNumberOfSections = pWoody->pNtHeaders->FileHeader.NumberOfSections;
    while (wNumberOfSections--)
    {
        if ((dwRva >= pSectionHeader->VirtualAddress)
            && (dwRva < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)))
        {
            return (pSectionHeader);
        }
        ++pSectionHeader;
    }
    return (NULL);
}

INT GetExecutableSection(PWOODY pWoody)
{
    pWoody->pExecutableSectionHeader = GetSectionHeaderFromRva(
        pWoody,
        pWoody->pNtHeaders->OptionalHeader.AddressOfEntryPoint
    );

    if (NULL == pWoody->pExecutableSectionHeader)
    {
        PrintError("GetExecutableSection", "No executable section found\n");
        return (RET_KO);
    }

    return (RET_OK);
}
