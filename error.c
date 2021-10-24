#include "woody.h"

void PrintError(PCSTR pszFunction, PCSTR pszCustomErrorMessage)
{
    LPSTR pMsgBuf = NULL;
    DWORD dwError = GetLastError();

    fprintf(stderr, "%s failed with error", pszFunction);
    if (NULL == pszCustomErrorMessage)
    {
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            dwError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPVOID)&pMsgBuf,
            0, NULL);

        fprintf(stderr, " %d", dwError);
    }
    fprintf(stderr, ": %s\n", pMsgBuf ? pMsgBuf : pszCustomErrorMessage);

    LocalFree(pMsgBuf);
}
