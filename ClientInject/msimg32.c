#include <Windows.h>


FARPROC pAlphaBlend;
void __declspec(naked) AlphaBlendStub()
{
    __asm jmp pAlphaBlend;
}

FARPROC pDllInitialize;
void __declspec(naked) DllInitializeStub()
{
    __asm jmp pDllInitialize;
}

FARPROC pGradientFill;
void __declspec(naked) GradientFillStub()
{
    __asm jmp pGradientFill;
}

FARPROC pTransparentBlt;
void __declspec(naked) TransparentBltStub()
{
    __asm jmp pTransparentBlt;
}

FARPROC pvSetDdrawflag;
void __declspec(naked) vSetDdrawflagStub()
{
    __asm jmp pvSetDdrawflag;
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
    )
{
    UNREFERENCED_PARAMETER(lpReserved);

    static HMODULE hMsImg32;
    static HMODULE hKernel32;

    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);

            hMsImg32 = LoadLibrary(TEXT("C:\\Windows\\system32\\msimg32.dll"));
            if (hMsImg32)
            {
                pAlphaBlend = GetProcAddress(hMsImg32, "AlphaBlend");
                pDllInitialize = GetProcAddress(hMsImg32, "DllInitialize");
                pGradientFill = GetProcAddress(hMsImg32, "GradientFill");
                pTransparentBlt = GetProcAddress(hMsImg32, "TransparentBlt");
                pvSetDdrawflag = GetProcAddress(hMsImg32, "vSetDdrawflag");
            }
            else
            {
                return FALSE;
            }

            hKernel32 = LoadLibrary(TEXT("C:\\Windows\\system32\\kernel32.dll"));
            LPBYTE pProc = (LPBYTE) (SIZE_T) GetProcAddress(hKernel32, "Process32NextW");

            DWORD flOldProtect;
            VirtualProtect(pProc, 5, PAGE_EXECUTE_READWRITE, &flOldProtect);
            pProc[0] = 0x31;
            pProc[1] = 0xC0;    // xor eax,eax
            pProc[2] = 0xC2;    // retn
            pProc[3] = 0x08;
            pProc[4] = 0x00;    // 0x0008

            break;
        case DLL_PROCESS_DETACH:
            FreeLibrary(hKernel32);
            return FreeLibrary(hMsImg32);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}