#include "woody.h"

INT MapFile(PCSTR pszFilePath, PWOODY pWoody)
{
    INT ret = RET_OK;
    HANDLE hFile;
    LARGE_INTEGER FileSize;
    HANDLE hFileMapping;

    hFile = CreateFileA(
        pszFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (INVALID_HANDLE_VALUE == hFile)
    {
        PrintError("CreateFileA (in MapFile)", NULL);
        ret = RET_KO;
        goto function_ret;
    }

    if (!(GetFileSizeEx(hFile, &FileSize)))
    {
        PrintError("GetFileSizeEx (in MapFile)", NULL);
        ret = RET_KO;
        goto close_file;
    }

    else if (FileSize.QuadPart > (LONGLONG)ULONG_MAX)
    {
        PrintError("MapFile", "File size too big\n");
        ret = RET_KO;
        goto close_file;
    }

    else if (FileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
    {
        PrintError("MapFile", "File size too small\n");
        ret = RET_KO;
        goto close_file;
    }

    pWoody->FileSize = FileSize.QuadPart;

    hFileMapping = CreateFileMappingA(
        hFile,
        NULL,
        PAGE_WRITECOPY,
        FileSize.HighPart,
        FileSize.LowPart,
        NULL
    );

    if (NULL == hFileMapping)
    {
        PrintError("CreateFileMappingA (in MapFile)", NULL);
        ret = RET_KO;
        goto close_file;
    }

    pWoody->pMappedFile = MapViewOfFile(
        hFileMapping,
        FILE_MAP_COPY,
        0,
        0,
        FileSize.QuadPart);

    if (NULL == pWoody->pMappedFile)
    {
        ret = RET_KO;
        PrintError("MapViewOfFile (in MapFile)", NULL);
    }

    CloseHandle(hFileMapping);
close_file:
    CloseHandle(hFile);
function_ret:
    return (ret);
}

INT GenerateNewFile(PWOODY pWoody)
{
    INT ret = RET_OK;
    HANDLE hFile;
    DWORD NbWritten;
    DWORD AlignDiff;
    PBYTE AlignBuf = NULL;

    hFile = CreateFileA(
        PACKED_FILENAME,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (NULL == hFile)
    {
        PrintError("CreateFileA (in GenerateNewFile)", NULL);
        return (RET_KO);
    }

    if (pWoody->FileSizeAligned > pWoody->FileSize)
    {
        AlignDiff = pWoody->FileSizeAligned - pWoody->FileSize;
        AlignBuf = LocalAlloc(LPTR, AlignDiff);
    }

    if ((FALSE == WriteFile(hFile, pWoody->pMappedFile, pWoody->FileSize, &NbWritten, NULL))
        || ((NULL != AlignBuf) && (FALSE == WriteFile(hFile, AlignBuf, AlignDiff, &NbWritten, NULL)))
        || (FALSE == WriteFile(hFile, pWoody->pNewSection, pWoody->NewSectionSizeAlignedRaw, &NbWritten, NULL)))
    {
        DeleteFileA(PACKED_FILENAME);
        PrintError("WriteFile (in GenerateNewFile)", NULL);
        ret = RET_KO;
    }

    if (NULL != AlignBuf)
    {
        LocalFree(AlignBuf);
    }

    CloseHandle(hFile);

    return (ret);
}
