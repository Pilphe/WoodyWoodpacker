#include "woody.h"

static VOID UpdateHeaders(PWOODY pWoody)
{
    pWoody->pNtHeaders->FileHeader.NumberOfSections += 1;
    pWoody->pNtHeaders->OptionalHeader.SizeOfImage += pWoody->NewSectionSizeAlignedVirtual;
    pWoody->pNtHeaders->OptionalHeader.AddressOfEntryPoint = (pWoody->pNewSectionHeader->VirtualAddress + ENCRYPTION_KEY_SIZE);

    if (pWoody->pNtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    {
        pWoody->pNtHeaders->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
    }

    pWoody->pExecutableSectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
}

static VOID EncryptExecutableSection(PWOODY pWoody)
{
    XorCipher(
        ((PBYTE)(pWoody->pMappedFile) + pWoody->pExecutableSectionHeader->PointerToRawData),
        pWoody->pExecutableSectionHeader->Misc.VirtualSize,
        pWoody->EncryptionKey
    );
}

static VOID InsertNewSectionHeader(PWOODY pWoody)
{
    memset(pWoody->pNewSectionHeader, '\0', sizeof(IMAGE_SECTION_HEADER));
    memcpy(pWoody->pNewSectionHeader->Name, NEW_SECTION_NAME, sizeof(NEW_SECTION_NAME));

    pWoody->pNewSectionHeader->Misc.VirtualSize = pWoody->PayloadSize;
    pWoody->pNewSectionHeader->VirtualAddress = pWoody->pNtHeaders->OptionalHeader.SizeOfImage;
    pWoody->pNewSectionHeader->SizeOfRawData = pWoody->NewSectionSizeAlignedRaw;
    pWoody->pNewSectionHeader->PointerToRawData = pWoody->FileSizeAligned;
    pWoody->pNewSectionHeader->Characteristics = (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
}

static INT CreateNewSection(PWOODY pWoody)
{
    DWORD PayloadEndToEntryPointOffset;

    pWoody->pNewSection = LocalAlloc(LPTR, pWoody->NewSectionSizeAlignedRaw);
    if (NULL == pWoody->pNewSection)
    {
        PrintError("LocalAlloc (in GeneratePayloadBuffer)", NULL);
        return (RET_KO);
    }

    memcpy(pWoody->pNewSection, &PayloadStart, pWoody->PayloadSize);
    memcpy(pWoody->pNewSection, pWoody->EncryptionKey, ENCRYPTION_KEY_SIZE);

    PayloadEndToEntryPointOffset = (pWoody->pNtHeaders->OptionalHeader.AddressOfEntryPoint
        - (pWoody->pNewSectionHeader->VirtualAddress + pWoody->PayloadSize));

    *(DWORD*)(pWoody->pNewSection + ExecutableSectionOffset) = pWoody->pExecutableSectionHeader->VirtualAddress;
    *(DWORD*)(pWoody->pNewSection + ExecutableSectionSizeOffset) = pWoody->pExecutableSectionHeader->Misc.VirtualSize;
    *(DWORD*)(pWoody->pNewSection + OriginalEntryPointJumpOffset) = PayloadEndToEntryPointOffset;

    return (RET_OK);
}

static INT GenerateEncryptionKey(PWOODY pWoody)
{
    NTSTATUS Status;

    Status = BCryptGenRandom(NULL, pWoody->EncryptionKey, ENCRYPTION_KEY_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!(NT_SUCCESS(Status)))
    {
        PrintError("BCryptGenRandom (in GenerateEncryptionKey)", "Failed to generate encryption key");
        return (RET_KO);
    }
    return (RET_OK);
}

INT PackerMain(PCSTR pFilePath)
{
    INT ret = RET_OK;
    WOODY Woody;

    memset(&Woody, '\0', sizeof(Woody));

    if ((RET_KO == GenerateEncryptionKey(&Woody))
        || (RET_KO == MapFile(pFilePath, &Woody))
        || (RET_KO == CheckNtHeaders(&Woody))
        || (RET_KO == CheckSectionsHeaders(&Woody))
        || (RET_KO == CheckTlsDirectory(&Woody)))
    {
        ret = RET_KO;
        goto unmap;
    }

    Woody.FileSizeAligned = AlignDword(Woody.FileSize, Woody.pNtHeaders->OptionalHeader.FileAlignment);
    Woody.pNewSectionHeader = GetNewSectionHeader(Woody.pNtHeaders);
    Woody.PayloadSize = PayloadSize;
    Woody.NewSectionSizeAlignedRaw = AlignDword(Woody.PayloadSize, Woody.pNtHeaders->OptionalHeader.FileAlignment);
    Woody.NewSectionSizeAlignedVirtual = AlignDword(Woody.PayloadSize, Woody.pNtHeaders->OptionalHeader.SectionAlignment);

    InsertNewSectionHeader(&Woody);

    if (RET_KO == CreateNewSection(&Woody))
    {
        ret = RET_KO;
        goto unmap;
    }

    UpdateHeaders(&Woody);
    EncryptExecutableSection(&Woody);
    ret = GenerateNewFile(&Woody);

    if (RET_OK == ret)
    {
        fprintf(stdout, "%s packed successfully\nEncryption key (hex): ", pFilePath);
        for (int i = 0; i < sizeof(Woody.EncryptionKey); ++i)
            fprintf(stdout, "%02hhX", Woody.EncryptionKey[i]);
        fprintf(stdout, "\n");
    }

    LocalFree(Woody.pNewSection);

unmap:
    if (NULL != Woody.pMappedFile)
        UnmapViewOfFile(Woody.pMappedFile);

    return (ret);
}
