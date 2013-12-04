// Thunderneko.cpp : 定义 DLL 应用程序的导出函数。
//

#include <stdio.h>
#include <Windows.h>
#include "Thunderneko.h"
#include "..\Migration\UMC.h"

wchar_t DNFMutantName [] = L"dbefeuate_ccen_khxfor_lcar_blr";
wchar_t DNFLauncherMutantName [] = L"NeopleLauncher";

int FoundCount = 0;

HOWTOCLOSE IdentifyDNFMutant(wchar_t* MutantName, ULONG NameLength)
{
    if (NameLength < 30)
        return DONT_CLOSE;

    wchar_t* RevName = new wchar_t[NameLength + 1];
    wcsncpy(RevName, MutantName, NameLength);
    wcsrev(RevName);
    if (wcsncmp(RevName, DNFMutantName, 30) == NULL || wcsncmp(RevName, DNFLauncherMutantName, 14) == NULL)
    {
        delete [] RevName;
        FoundCount++;
        return CLOSE_DIRECT;
    }
    delete [] RevName;
    return DONT_CLOSE;
}

int __stdcall MoeMoeSorayuki(void* Useless)
{
    FoundCount = 0;
    if (!EnumerateAndCloseMutant(IdentifyDNFMutant))
    {
        FoundCount = -1;
    }
    return FoundCount;
}

int __stdcall MoeMoeAndExit(void* Useless)
{
    FreeLibraryAndExitThread(hMyModule, MoeMoeSorayuki(NULL));
    return 0;
}