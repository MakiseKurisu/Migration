// Migration.cpp : 定义应用程序的入口点。
//

#include <Windows.h>
#include <CommCtrl.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <stdlib.h>
#include "..\Share\UMC.h"
#include "..\Share\RTL.h"
#include "res\Resource.h"

typedef VOID(WINAPI *GNSITYPE)(LPSYSTEM_INFO lpSystemInfo);
WCHAR DNFMutantName[] = L"dbefeuate_ccen_khxfor_lcar_blr";
WCHAR DNFIPCMutantName[] = L"IPC_INFO";
WCHAR DNFLauncherMutantName[] = L"NeopleLauncher";
WCHAR DNFClientMutantName[] = L"NeopleDNFClient";
int FoundCount = 0;
BOOL RunningOnX86 = TRUE;

HWND hMainWindow = NULL;

// 检测是否是64位操作系统，x64返回1，x86返回0，否则返回2
WORD GetProcessorArchitecture()
{
    GNSITYPE GetNativeSystemInfo = (GNSITYPE) GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetNativeSystemInfo");
    if (!GetNativeSystemInfo)
    {
        return PROCESSOR_ARCHITECTURE_UNKNOWN;
    }

    SYSTEM_INFO si;
    RtlZeroMemory(&si, sizeof(si));
    GetNativeSystemInfo(&si);
    return si.wProcessorArchitecture;
}

BOOL AdjustPrivilege(BOOL bEnable)
{
    HANDLE hToken = 0;
    TOKEN_PRIVILEGES tkp;

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = 0;
    if (bEnable) tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &tkp.Privileges[0].Luid))
    {
        return FALSE;
    }
    if (OpenProcessToken((HANDLE) -1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        if (AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL))
        {
            CloseHandle(hToken);
            return TRUE;
        }
        CloseHandle(hToken);
    }
    return FALSE;
}

HOWTOCLOSE IdentifyDNFMutant(LPCWSTR MutantName, ULONG NameLength)
{
    ULONG nDNFMutantName = sizeof(DNFMutantName) / sizeof(DNFMutantName[0]) - 1;
    ULONG nDNFIPCMutantName = sizeof(DNFIPCMutantName) / sizeof(DNFIPCMutantName[0]) - 1;
    ULONG nDNFLauncherMutantName = sizeof(DNFLauncherMutantName) / sizeof(DNFLauncherMutantName[0]) - 1;
    ULONG nDNFClientMutantName = sizeof(DNFClientMutantName) / sizeof(DNFClientMutantName[0]) - 1;

    if (!MutantName || NameLength < 15)
    {
        return DONT_CLOSE;
    }

    int i = lstrlen(MutantName);
    MutantName += i;
    for (; i && (--MutantName)[0] != L'\\'; i--);
    MutantName++;

    if (!Mstrcmpn(MutantName, DNFMutantName, nDNFMutantName) || !Mstrcmpn(MutantName, DNFIPCMutantName, nDNFIPCMutantName) || !Mstrcmpn(MutantName, DNFClientMutantName, nDNFClientMutantName))
    {
        FoundCount++;

        if (RunningOnX86)
        {
            return CLOSE_INJECT;
        }
        else
        {
            return CLOSE_DIRECT;
        }
    }
    else if (!Mstrcmpn(MutantName, DNFLauncherMutantName, nDNFLauncherMutantName))
    {
        FoundCount++;
        return CLOSE_DIRECT;
    }
    return DONT_CLOSE;
}

BOOL ShowHideAllDnf(BOOL bShow)
{
    HWND EvilParent = hMainWindow;
    HWND Migration = NULL;
    if (!bShow)
    {
        EvilParent = NULL;
        Migration = hMainWindow;
    }
    HWND hWnd = NULL;

    for (;;)
    {
        hWnd = FindWindowEx(EvilParent, NULL, L"地下城与勇士", L"地下城与勇士");
        if (!hWnd)
        {
            break;
        }

        // Install msimg32.dll
        if (!bShow)
        {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL | TH32CS_SNAPMODULE32, 0);
            if (hSnapshot)
            {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                if (Process32First(hSnapshot, &pe))
                {
                    do
                    {
                        if (!lstrcmpi(pe.szExeFile, TEXT("dnf.exe")))
                        {
                            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL | TH32CS_SNAPMODULE32, pe.th32ProcessID);
                            if (hSnapshot)
                            {
                                MODULEENTRY32 me;
                                me.dwSize = sizeof(me);
                                Module32First(hSnapshot, &me);
                                for (int i = lstrlen(me.szExePath); i >= 0 && me.szExePath[i] != TEXT('\\'); me.szExePath[i--] = TEXT('\0'));
                                lstrcat(me.szExePath, TEXT("TCLS\\msimg32.dll"));

                                TCHAR szFilename[MAX_PATH];
                                GetModuleFileName(NULL, szFilename, _countof(szFilename));
                                for (int i = lstrlen(szFilename); i >= 0 && szFilename[i] != TEXT('\\'); szFilename[i--] = TEXT('\0'));
                                lstrcat(szFilename, TEXT("msimg32.dll"));

                                if (!CopyFile(szFilename, me.szExePath, TRUE))
                                {
                                    if (GetLastError() != ERROR_FILE_EXISTS)
                                    {
                                        MessageBox(hMainWindow, TEXT("糟糕，无法安装msimg32.dll咧...\n\n如果双开失败了，请手动将双开目录下的msimg32.dll复制到DNF安装目录下TCLS目录内。"), TEXT("错误"), MB_OK | MB_ICONSTOP);
                                    }
                                }

                                CloseHandle(hSnapshot);
                            }
                        }
                    } while (Process32Next(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
        }

        if (bShow)
        {
            SetParent(hWnd, Migration);
        }
        FlashWindow(hWnd, TRUE);
        ShowWindow(hWnd, bShow ? SW_SHOW : SW_HIDE);
        FlashWindow(hWnd, TRUE);
        if (!bShow)
        {
            SetParent(hWnd, Migration);
        }
    }
    return TRUE;
}

void FuckJunkProcess()
{
    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32 = { 0 };
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD PidCollect[16] = { 0 };
    ULONG_PTR Collected = 0;
    int DNFCount = 0;

    pe32.dwSize = sizeof(pe32);
    if (Process32First(hProcessSnap, &pe32))
    {
        do
        {
            if (!lstrcmpi(pe32.szExeFile, L"qqlogin.exe") || !lstrcmpi(pe32.szExeFile, L"QQDL.exe") || !lstrcmpi(pe32.szExeFile, L"TenSafe.exe"))
            {
                PidCollect[Collected++] = pe32.th32ProcessID;
            }
            else if (!lstrcmpi(pe32.szExeFile, L"dnf.exe"))
            {
                DNFCount++;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    if (DNFCount >= 2)
    {
        for (ULONG_PTR i = 0; i < Collected; i++)
        {
            HANDLE hMLGB = OpenProcess(PROCESS_TERMINATE, FALSE, PidCollect[i]);
            TerminateProcess(hMLGB, 0);
            CloseHandle(hMLGB);
        }
    }
}

int InjectDllAndRunFunc(LPCWSTR pszDllFile, DWORD dwProcessId, SIZE_T FuncOffset)
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD dwSize = 0;
    LPSTR pszRemoteBuf = NULL;
    LPTHREAD_START_ROUTINE lpThreadFun = NULL;

    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessId);
    if (!hProcess)
    {
        return -2;
    }

    dwSize = (DWORD) ((lstrlen(pszDllFile) + 1) * 2);
    pszRemoteBuf = (LPSTR) VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pszRemoteBuf)
    {
        CloseHandle(hProcess);
        return -2;
    }

    if (!WriteProcessMemory(hProcess, pszRemoteBuf, (LPVOID) pszDllFile, dwSize, NULL))
    {
        VirtualFreeEx(hProcess, pszRemoteBuf, dwSize, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return -2;
    }

    lpThreadFun = (LPTHREAD_START_ROUTINE) LoadLibraryW;

    if (!lpThreadFun)
    {
        VirtualFreeEx(hProcess, pszRemoteBuf, dwSize, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return -2;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, pszRemoteBuf, 0, NULL);
    if (!hThread)
    {
        hThread = OsCreateRemoteThread2(hProcess, NULL, 0, lpThreadFun, pszRemoteBuf, 0, NULL);
    }
    if (!hThread)
    {
        VirtualFreeEx(hProcess, pszRemoteBuf, dwSize, MEM_DECOMMIT);
        CloseHandle(hProcess);
        return -2;
    }

    HMODULE hDLLModule = NULL;
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, (LPDWORD) &hDLLModule);

    VirtualFreeEx(hProcess, pszRemoteBuf, dwSize, MEM_DECOMMIT);
    CloseHandle(hThread);

    lpThreadFun = (LPTHREAD_START_ROUTINE) ((SIZE_T) hDLLModule + FuncOffset);

    hThread = CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, pszRemoteBuf, 0, NULL);
    if (!hThread)
    {
        hThread = OsCreateRemoteThread2(hProcess, NULL, 0, lpThreadFun, pszRemoteBuf, 0, NULL);
    }
    if (!hThread)
    {
        CloseHandle(hProcess);
        return -2;
    }

    WaitForSingleObject(hThread, INFINITE);
    int Result = -2;
    GetExitCodeThread(hThread, (LPDWORD) &Result);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return Result;
}

int InjectEnumerateAndCloseMutant()
{
    HMODULE hThunderNeko = LoadLibrary(L"ThunderNeko.dll");
    if (!hThunderNeko)
    {
        return -1;
    }

    FARPROC FuncAddress = GetProcAddress(hThunderNeko, "MoeMoeAndExit");
    if (!FuncAddress)
    {
        return -1;
    }

    WCHAR FullPath[MAX_PATH * 2];
    SIZE_T FuncOffset = (SIZE_T) FuncAddress - (SIZE_T) hThunderNeko;
    GetModuleFileName(hThunderNeko, FullPath, MAX_PATH * 2);
    FreeLibrary(hThunderNeko);

    DWORD MyTar = 0;
    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32 = { 0 };
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    pe32.dwSize = sizeof(pe32);
    if (Process32First(hProcessSnap, &pe32))
    {
        do
        {
            if (!lstrcmpi(pe32.szExeFile, L"svchost.exe"))
            {
                MyTar = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);

    return InjectDllAndRunFunc(FullPath, MyTar, FuncOffset);
}

INT_PTR CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    int wmId;

    switch (message)
    {
        case WM_INITDIALOG:
            hMainWindow = hWnd;
#ifdef _WIN64
            {
                WCHAR WindowTitle[200] = { 0 };
                GetWindowText(hWnd, WindowTitle, 200);
                lstrcat(WindowTitle, L" (x64)");
                SetWindowText(hWnd, WindowTitle);
            }
#endif
            return TRUE;
        case WM_COMMAND:
            wmId = LOWORD(wParam);
            switch (wmId)
            {
                case IDCANCEL:
                    EndDialog(hWnd, 0);
                    break;
                case IDC_CLOSEHANDLE:
                {
#ifndef _WIN64
                    if (!IsWindowsVistaOrGreater() && RunningOnX86)
                    {
                        // 这年头用XP的没人权
                        FoundCount = InjectEnumerateAndCloseMutant();
                        if (FoundCount == -1)
                        {
                            MessageBox(hWnd, L"您正在使用的Windows操作系统版本小于Windows Vista，因此程序需要ThunderNeko.dll放置在本程序目录下才能正常工作。\n\n但是您的ThunderNeko.dll很可能损坏或不存在。", L"这年头用XP的没人权", MB_ICONINFORMATION | MB_OK);
                        }
                        if (FoundCount == -2)
                        {
                            MessageBox(hWnd, L"插入失败...", L"...", MB_ICONSTOP | MB_OK);
                        }
                    }
                    else
#endif
                    {
                        FoundCount = 0;
                        if (!EnumerateAndCloseMutant(IdentifyDNFMutant))
                        {
                            MessageBox(hWnd, L"句柄对象枚举中出现了一些问题，是权限不够吗？\n\n如果您使用的操作系统是Windows XP/2003 x64 Edition，请务必下载x64版本使用，可能可以解决这个问题。", L"错误", MB_ICONSTOP | MB_OK);
                            break;
                        }
                    }
                    if (FoundCount == 0)
                    {
                        MessageBox(hWnd, L"咱根本就没找到人...", L"错误", MB_OK | MB_ICONSTOP);
                    }
                    else if (FoundCount > 1)
                    {
                        MessageBox(hWnd, L"说真的，我最讨厌多P了..", L"成功", MB_OK | MB_ICONINFORMATION);
                    }
                    else if (FoundCount == 1)
                    {
                        MessageBox(hWnd, L"呃，就一发，就一发。", L"完成", MB_OK | MB_ICONINFORMATION);
                    }
                    break;
                }
                case IDC_HIDEWINDOW:
                    ShowHideAllDnf(FALSE);
                    break;
                case IDC_SHOWWINDOW:
                    ShowHideAllDnf(TRUE);
                    FuckJunkProcess();
                    break;
            }
            break;
        case WM_CLOSE:
            ExitProcess(0);
            break;
    }
    return 0;
}

INT_PTR APIENTRY Main()
{
    if (!AdjustPrivilege(TRUE))
    {
        MessageBox(NULL, L"无法取得调教权限。\n\n请使用管理员权限运行本程序。", L"错误", MB_ICONSTOP | MB_OK);
        return 0;
    }

    InitCommonControls();

    if (GetProcessorArchitecture() != PROCESSOR_ARCHITECTURE_INTEL)
    {
        RunningOnX86 = FALSE;
#ifndef _WIN64
        MessageBox(NULL, L"您当前正在一个非32位版本Windows上使用本程序的32位版本，这有可能造成本程序工作不正常，请尽量获取一份原生版本的Migration.exe来使用。", L"提示", MB_OK | MB_ICONINFORMATION);
#endif
    }

    return DialogBox(NULL, MAKEINTRESOURCE(IDD_MAINDLG), NULL, WndProc);
}