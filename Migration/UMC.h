// Universal Mutant Closer's Header - UMC.h 
// Created by Riatre(aka. 258921) @ 2010/08/13

#pragma once

#include <windows.h>
#include <tlhelp32.h>

enum HOWTOCLOSE
{
    DONT_CLOSE = 0,
    CLOSE_DIRECT,
    CLOSE_INJECT
};

typedef HOWTOCLOSE(*CLOSECALLBACK)(wchar_t* MutantName, ULONG NameLength);

BYTE GetObjectTypeNumber(wchar_t* ObjectName);
BOOL RemoteCloseHandle(HANDLE hProcess, HANDLE hHandle);
BOOL EnumerateAndCloseMutant(CLOSECALLBACK ShouldClose);

HANDLE WINAPI OsCreateRemoteThread2(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);