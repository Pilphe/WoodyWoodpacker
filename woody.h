#pragma once

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <limits.h>

#define RET_OK 0
#define RET_KO 1
#define ENCRYPTION_KEY_SIZE 16
#define NEW_SECTION_NAME ".woody"
#define PACKED_FILENAME "woody.exe"

extern const DWORD    PayloadSize;
extern const DWORD    ExecutableSectionOffset;
extern const DWORD    ExecutableSectionSizeOffset;
extern const DWORD    OriginalEntryPointJumpOffset;
extern BYTE           PayloadStart;
extern VOID           XorCipher(PVOID pCode, LONGLONG llCodeSize, PVOID pKey);

typedef struct _WOODY
{
    PVOID                   pMappedFile;
    PIMAGE_NT_HEADERS64     pNtHeaders;
    PIMAGE_SECTION_HEADER   pSectionHeaders;
    PIMAGE_SECTION_HEADER   pExecutableSectionHeader;
    PIMAGE_SECTION_HEADER   pNewSectionHeader;
    PBYTE                   pNewSection;
    DWORD                   FileSize;
    DWORD                   FileSizeAligned;
    DWORD                   PayloadSize;
    DWORD                   NewSectionSizeAlignedRaw;
    DWORD                   NewSectionSizeAlignedVirtual;
    BYTE                    EncryptionKey[ENCRYPTION_KEY_SIZE];
} WOODY, *PWOODY;

VOID                    PrintError(PCSTR pszFunction, PCSTR pszCustomErrorMessage);

INT                     PackerMain(PCSTR pFilePath);

INT                     GenerateNewFile(PWOODY pWoody);
INT                     MapFile(PCSTR pszFilePath, PWOODY pWoody);

INT                     CheckNtHeaders(PWOODY pWoody);
INT                     CheckSectionsHeaders(PWOODY pWoody);
INT                     CheckTlsDirectory(PWOODY pWoody);

DWORD                   AlignDword(DWORD dwToAlign, DWORD dwAlignment);
PIMAGE_NT_HEADERS64     GetNtHeaders(PVOID pMappedFile);
PIMAGE_SECTION_HEADER   GetSectionTable(PIMAGE_NT_HEADERS64 pNtHeaders);
PIMAGE_SECTION_HEADER   GetNewSectionHeader(PIMAGE_NT_HEADERS64 pNtHeaders);
PIMAGE_SECTION_HEADER   GetSectionHeaderFromRva(PWOODY pWoody, DWORD dwRva);
INT                     GetExecutableSection(PWOODY pWoody);
