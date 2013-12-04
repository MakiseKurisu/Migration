// Thunderneko.cpp : 定义 DLL 应用程序的导出函数。
//

#include <stdio.h>
#include <Windows.h>
#include "Thunderneko.h"
#include "..\Share\UMC.h"

WCHAR DNFMutantName [] = L"dbefeuate_ccen_khxfor_lcar_blr";
WCHAR DNFLauncherMutantName [] = L"NeopleLauncher";

int FoundCount = 0;

HOWTOCLOSE IdentifyDNFMutant(LPCWSTR MutantName, ULONG NameLength)
{
    if (NameLength < 30)
        return DONT_CLOSE;

    LPWSTR RevName = new WCHAR[NameLength + 1];
    lstrcpyn(RevName, MutantName, NameLength);
    if (wcsncmp(RevName, DNFMutantName, 30) == NULL || wcsncmp(RevName, DNFLauncherMutantName, 14) == NULL)
    {
        delete [] RevName;
        FoundCount++;
        return CLOSE_DIRECT;
    }
    delete [] RevName;
    return DONT_CLOSE;
}

int __stdcall MoeMoeSorayuki(LPVOID Useless)
{
    FoundCount = 0;
    if (!EnumerateAndCloseMutant(IdentifyDNFMutant))
    {
        FoundCount = -1;
    }
    return FoundCount;
}

VOID __stdcall MoeMoeAndExit(LPVOID Useless)
{
    FreeLibraryAndExitThread(hMyModule, MoeMoeSorayuki(NULL));
}