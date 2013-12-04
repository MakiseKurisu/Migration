// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <Windows.h>
#include "Thunderneko.h"

// For dirty XP Hack...
// 别吐槽实现脏了，这根本就是计划外的事

HMODULE hMyModule = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		wcsrev(DNFMutantName);
		wcsrev(DNFLauncherMutantName);
		hMyModule = hModule;
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

