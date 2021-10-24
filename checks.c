#include "woody.h"

static inline BOOL IsOutOfMap(PWOODY pWoody, PBYTE pToDiff)
{
    return ((ptrdiff_t)(pToDiff - (PBYTE)(pWoody->pMappedFile)) > pWoody->FileSize);
}

static BOOL IsPacked(PIMAGE_NT_HEADERS64 pNtHeaders)
{
    PIMAGE_SECTION_HEADER pLastSection;

    pLastSection = (PIMAGE_SECTION_HEADER)(GetSectionTable(pNtHeaders)
        + (pNtHeaders->FileHeader.NumberOfSections - 1));

    return (0 == memcmp(
        pLastSection->Name,
        NEW_SECTION_NAME,
        sizeof(NEW_SECTION_NAME)
    ));
}

INT CheckNtHeaders(PWOODY pWoody)
{
    if (IMAGE_DOS_SIGNATURE != *(WORD*)(pWoody->pMappedFile))
    {
        PrintError("CheckNtHeaders", "Not a PE file");
        return (RET_KO);
    }

    pWoody->pNtHeaders = GetNtHeaders(pWoody->pMappedFile);

    if (IsOutOfMap(pWoody, (PBYTE)(pWoody->pNtHeaders))
        || IsOutOfMap(pWoody, ((PBYTE)(pWoody->pMappedFile) + pWoody->pNtHeaders->OptionalHeader.SizeOfHeaders)))
    {
        PrintError("CheckNtHeaders", "Corrupted PE header");
        return (RET_KO);
    }

    if (pWoody->pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        PrintError("CheckNtHeaders", "Not a PE file");
        return (RET_KO);
    }

    if ((pWoody->pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        || (pWoody->pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        || !(pWoody->pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        || (pWoody->pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        PrintError("CheckNtHeaders", "Unsupported PE type");
        return (RET_KO);
    }

    return (RET_OK);
}

INT CheckSectionsHeaders(PWOODY pWoody)
{
    DWORD dwSectionTableSize;

    pWoody->pSectionHeaders = GetSectionTable(pWoody->pNtHeaders);
    dwSectionTableSize = (pWoody->pNtHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    if ((IsOutOfMap(pWoody, (PBYTE)(pWoody->pSectionHeaders)))
        || (IsOutOfMap(pWoody, ((PBYTE)(pWoody->pSectionHeaders) + dwSectionTableSize)))
        || ((DWORD)(sizeof(IMAGE_NT_HEADERS64) + dwSectionTableSize) >= pWoody->pNtHeaders->OptionalHeader.SizeOfHeaders))
    {
        PrintError("CheckSectionsHeaders", "Corrupted section table");
        return (RET_KO);
    }

    if (IsPacked(pWoody->pNtHeaders))
    {
        PrintError("CheckSectionsHeaders", "Executable file already packed");
        return (RET_KO);
    }

    if (pWoody->pNtHeaders->OptionalHeader.SizeOfHeaders
        - (DWORD)(sizeof(IMAGE_NT_HEADERS64)
            + dwSectionTableSize) < sizeof(IMAGE_SECTION_HEADER))
    {
        PrintError("CheckSectionsHeaders", "Section table cave too small, cannot add a new one");
        return (RET_KO);
    }

    if ((RET_KO == GetExecutableSection(pWoody))
        || IsOutOfMap(pWoody, ((PBYTE)(pWoody->pMappedFile)
            + pWoody->pExecutableSectionHeader->PointerToRawData))
        || IsOutOfMap(pWoody, ((PBYTE)(pWoody->pMappedFile)
            + pWoody->pExecutableSectionHeader->PointerToRawData
            + pWoody->pExecutableSectionHeader->SizeOfRawData))
        || IsOutOfMap(pWoody, ((PBYTE)(pWoody->pMappedFile)
            + pWoody->pExecutableSectionHeader->PointerToRawData
            + pWoody->pExecutableSectionHeader->Misc.VirtualSize)))
    {
        PrintError("CheckSectionsHeaders", "Executable section table entry corrupted");
        return (RET_KO);
    }

    return (RET_OK);
}

INT CheckTlsDirectory(PWOODY pWoody)
{
    DWORD VirtualAddress;
    DWORD Size;
    PIMAGE_TLS_DIRECTORY64 pTlsDirectory;
    PIMAGE_SECTION_HEADER pSectionHeader;
    PIMAGE_TLS_CALLBACK* TlsCallbacks;

    VirtualAddress = pWoody->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    Size = pWoody->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if ((VirtualAddress > 0) && (Size > 0))
    {
        pSectionHeader = GetSectionHeaderFromRva(pWoody, VirtualAddress);
        if (NULL == pSectionHeader)
        {
            return (RET_OK);
        }

        pTlsDirectory = (PIMAGE_TLS_DIRECTORY64)((PBYTE)(pWoody->pMappedFile)
            + (VirtualAddress - pSectionHeader->VirtualAddress)
            + pSectionHeader->PointerToRawData);

        if (IsOutOfMap(pWoody, (PBYTE)pTlsDirectory))
        {
            PrintError("CheckTlsDirectory", "Invalid TLS directory");
            return (RET_KO);
        }

        if (0 == pTlsDirectory->AddressOfCallBacks)
        {
            return (RET_OK);
        }

        VirtualAddress = pTlsDirectory->AddressOfCallBacks - pWoody->pNtHeaders->OptionalHeader.ImageBase;
        pSectionHeader = GetSectionHeaderFromRva(pWoody, VirtualAddress);

        if (NULL == pSectionHeader)
        {
            return (FALSE);
        }

        TlsCallbacks = (PIMAGE_TLS_CALLBACK*)((PBYTE)(pWoody->pMappedFile)
            + (VirtualAddress - pSectionHeader->VirtualAddress)
            + pSectionHeader->PointerToRawData);

        if (IsOutOfMap(pWoody, (PBYTE)TlsCallbacks))
        {
            PrintError("CheckTlsDirectory", "Invalid TLS callbacks address");
            return (RET_KO);
        }

        if (NULL != *TlsCallbacks)
        {
            PrintError("CheckTlsDirectory", "TLS callbacks are not supported");
            return (RET_KO);
        }
    }
    return (RET_OK);
}
