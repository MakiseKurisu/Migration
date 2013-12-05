#include <windows.h>

int Mstrcmpn(LPCWSTR a, LPCWSTR b, int n)
{
    while (n--)
    {
        if (a[n] != b[n])
        {
            return a[n] - b[n];
        }
    }
    return 0;
}

#pragma function(memset)
void * memset(void * pTarget, int value, size_t cbTarget)
{
    LPBYTE p = (LPBYTE) pTarget;
    while (cbTarget--)
    {
        *p++ = (BYTE) value;
    }
    return pTarget;
}