// Universal Mutant Closer's Implementation - UMC.cpp
// Created by Riatre(aka. 258921) @ 2010/08/13
// Need to refact,really,really. 

#include "ntdll.h"
#include "UMC.h"
#include "RTL.h"

USHORT ProcessTypeNumber = 0xFFFF;
USHORT MutantTypeNumber = 0xFFFF;

// 无节抄！
HANDLE WINAPI OsCreateRemoteThread2(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId)
{
    //by 80695073(QQ) 
    //email kiss2008ufo@yahoo.com.cn

    CONTEXT    context = { CONTEXT_FULL };
    CLIENT_ID  cid;
    DWORD    ret;
    HANDLE    hThread = NULL;
    SIZE_T    StackReserve;
    SIZE_T    StackCommit = 0x1000;
    ULONG_PTR  Stack = 0;
    INITIAL_TEB InitialTeb;
    ULONG    x;
    const CHAR myBaseThreadInitThunk[] =
    {
        //   00830000    8BFF            mov     edi, edi
        '\x8B', '\xFF',
        //   00830002    55              push    ebp
        '\x55',
        //   00830003    8BEC            mov     ebp, esp
        '\x8B', '\xEC',
        //   00830005    51              push    ecx   //ntdll.RtlExitUserThread
        '\x51',
        //   00830006    53              push    ebx   //参数
        '\x53',
        //   00830007    FFD0            call    eax   //函数地址
        '\xFF', '\xD0',
        //   00830009    59              pop     ecx   //恢复结束函数地址
        '\x59',
        //   0083000A    50              push    eax   //将刚才的结果压栈
        '\x50',
        //   0083000B    FFD1            call    ecx   //调用RtlExitUserThread 结束
        '\xFF', '\xD1',
        //   0083000D    90              nop
        '\x90'
    };
    PVOID  pBaseThreadThunk = NULL; //不能释放

    //0、分配非OS的加载函数
    StackReserve = 0x1000;
    ret = ZwAllocateVirtualMemory(hProcess,
        /*&stack.ExpandableStackBottom*/(LPVOID*) &pBaseThreadThunk,
        0,
        &StackReserve,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }
    ret = ZwWriteVirtualMemory(hProcess,
        pBaseThreadThunk,
        (LPVOID) myBaseThreadInitThunk,
        sizeof(myBaseThreadInitThunk), &x);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }
    cid.UniqueProcess = hProcess;

    //1、准备堆栈
    StackReserve = 0x10000;
    ret = ZwAllocateVirtualMemory(hProcess,
        /*&stack.ExpandableStackBottom*/(LPVOID*) &Stack,
        0,
        &StackReserve,
        MEM_RESERVE,
        PAGE_READWRITE);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }

    InitialTeb.AllocatedStackBase = (PVOID) Stack;
    InitialTeb.StackBase = (PVOID) (Stack + StackReserve);

    /* Update the Stack Position */
    Stack += StackReserve - StackCommit;

    Stack -= 0x1000;
    StackCommit += 0x1000;

    /* Allocate memory for the stack */
    ret = ZwAllocateVirtualMemory(hProcess,
        (LPVOID*) &Stack,
        0,
        &StackCommit,
        MEM_COMMIT,
        PAGE_READWRITE);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }
    InitialTeb.StackLimit = (LPVOID) Stack;

    StackReserve = 0x1000;
    ret = ZwProtectVirtualMemory(hProcess, (LPVOID*) &Stack, &StackReserve, PAGE_READWRITE | PAGE_GUARD, &x);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }
    /* Update the Stack Limit keeping in mind the Guard Page */
    InitialTeb.StackLimit = (PVOID) ((ULONG_PTR) InitialTeb.StackLimit - 0x1000);
    //2、准备CONTEXT
    //  CONTEXT context = {CONTEXT_FULL}; 
    ret = ZwGetContextThread(GetCurrentThread(), &context);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }
#ifdef _WIN64
    context.Rsp = (ULONG_PTR) InitialTeb.StackBase;
    context.Rip = (ULONG_PTR) pBaseThreadThunk; //这里填写需要加载的地址，不过需要自己终结自己
    context.Rbx = (ULONG_PTR) lpParameter;
    //other init
    //must
    context.Rax = (ULONG_PTR) lpStartAddress;
    context.Rcx = (ULONG_PTR) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlExitUserThread"); //ntdll.RtlExitUserThread
    context.Rdx = 0x00000000; //nouse
#else
    context.Esp = (ULONG_PTR) InitialTeb.StackBase;
    context.Eip = (ULONG_PTR) pBaseThreadThunk; //这里填写需要加载的地址，不过需要自己终结自己
    context.Ebx = (ULONG_PTR) lpParameter;
    //other init
    //must
    context.Eax = (ULONG_PTR) lpStartAddress;
    context.Ecx = (ULONG_PTR) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlExitUserThread"); //ntdll.RtlExitUserThread
    context.Edx = 0x00000000; //nouse
#endif
    ret = ZwCreateThread(&hThread, THREAD_ALL_ACCESS, 0, hProcess, &cid, &context, &InitialTeb, TRUE);
    if (!(NT_SUCCESS(ret)))
    {
        //失败
        goto OsCreateRemoteThread2Ret;
        //end
    }
    if (lpThreadId)
    {
        *lpThreadId = (DWORD) cid.UniqueThread;
    }
    if (!(dwCreationFlags & CREATE_SUSPENDED))
    {
        ZwResumeThread(hThread, NULL);
    }
OsCreateRemoteThread2Ret:
    return hThread;
}

BYTE GetObjectTypeNumber(LPCWSTR ObjectName)
{
    BYTE TypeNumber = (BYTE) -1;
    ULONG cbReqLength;
    LPBYTE OutBuffer = (LPBYTE) GlobalAlloc(GPTR, sizeof(BYTE) * 100);
    RtlZeroMemory(OutBuffer, 100);
    ZwQueryObject(NULL, ObjectAllTypesInformation, OutBuffer, 100, &cbReqLength);
    GlobalFree(OutBuffer);
    OutBuffer = (LPBYTE) GlobalAlloc(GPTR, sizeof(BYTE) * cbReqLength);
    ZwQueryObject(NULL, ObjectAllTypesInformation, OutBuffer, cbReqLength, &cbReqLength);

    OBJECT_TYPES_INFORMATION* Types = (OBJECT_TYPES_INFORMATION*) OutBuffer;
    OBJECT_TYPE_INFORMATION* Type = Types->ObjectTypeInformation;
    for (BYTE i = 0; i < Types->NumberOfObjectsTypes; i++)
    {
        if (!Mstrcmpn(Type->TypeName.Buffer, ObjectName,
            Type->TypeName.Length < wcslen(ObjectName) ? Type->TypeName.Length : lstrlen(ObjectName)))
        {
            // Found!
            TypeNumber = i;
            break;
        }
        Type = (POBJECT_TYPE_INFORMATION) ((LPBYTE) Type + Type->TypeName.MaximumLength);
        Type = (POBJECT_TYPE_INFORMATION) ((LPBYTE) Type + sizeof(OBJECT_TYPE_INFORMATION));
        Type = (POBJECT_TYPE_INFORMATION) ((LPBYTE) Type + (sizeof(ULONG) -(DWORD) Type % sizeof(ULONG)) % sizeof(ULONG));  // For Align
    }
    GlobalFree(OutBuffer);
    if (TypeNumber != -1)
    {
        TypeNumber++; // "Number" begins from 1.
        if (IsWindows7OrGreater())
        {
            // Windows 7 Fix, Don't ask me why but it works.
            TypeNumber++;
        }
    }
    return TypeNumber;
}

BOOL RemoteCloseHandle(HANDLE hProcess, HANDLE hHandle)
{
    return NT_SUCCESS(ZwDuplicateObject(hProcess, hHandle, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE));
}

BOOL InjectRemoteCloseHandle(DWORD TargetProcessId, HANDLE hProcess, HANDLE hHandle)
{
    // x64不适用！（考虑到要插入的进程是原生x64，恐怕..）
    BYTE CloseCode[] = {
        /*push DUPLICATE_CLOSE_SOURCE*/
        0x6A, 0x01,
        /*push 0*/
        0x6A, 0x00,
        /*push 0*/
        0x6A, 0x00,
        /*push 0*/
        0x6A, 0x00,
        /*push 0*/
        0x6A, 0x00,
        /*push hHandle(+11)*/
        0x68, 0x00, 0x00, 0x00, 0x00,
        /*push hProcess(+16)*/
        0x68, 0x00, 0x00, 0x00, 0x00,
        /*mov eax,ZwDuplicateObject(+21)*/
        0xB8, 0x00, 0x00, 0x00, 0x00,
        /*call eax*/
        0xFF, 0xD0,
        /*push hProcess(+28)*/
        0x68, 0x00, 0x00, 0x00, 0x00,
        /*mov eax,ZwClose(+33)*/
        0xB8, 0x00, 0x00, 0x00, 0x00,
        /*call eax*/
        0xFF, 0xD0,
        /*retn 4*/
        0xC2, 0x04, 0x00
    };

    HANDLE hInjectProcess = NULL;
    HANDLE hThread = NULL;
    DWORD dwSize = 0;
    LPBYTE lpszRemoteBuf = NULL;
    LPTHREAD_START_ROUTINE lpThreadFun = NULL;

    hInjectProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetProcessId); // 不够WS，不过够了~
    if (!hInjectProcess)
    {
        return FALSE;
    }

    HANDLE TarhProcess = NULL;
    dwSize = sizeof(CloseCode) +1;
    lpszRemoteBuf = (LPBYTE) VirtualAllocEx(hInjectProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ZwDuplicateObject((HANDLE) -1, hProcess, hInjectProcess, &TarhProcess, PROCESS_ALL_ACCESS, 0, 0);
    *(HANDLE*) (CloseCode + 11) = hHandle;
    *(HANDLE*) (CloseCode + 16) = TarhProcess;
    *(HANDLE*) (CloseCode + 28) = TarhProcess;
    *(PZWCLOSE*) (CloseCode + 33) = ZwClose;
    *(PZWDUMPLICATEOBJECT*) (CloseCode + 21) = ZwDuplicateObject;

    if (!lpszRemoteBuf)
    {
        CloseHandle(hInjectProcess);
        return FALSE;
    }

    if (!WriteProcessMemory(hInjectProcess, lpszRemoteBuf, CloseCode, sizeof(CloseCode), NULL))
    {
        VirtualFreeEx(hInjectProcess, lpszRemoteBuf, dwSize, MEM_DECOMMIT);
        CloseHandle(hInjectProcess);
        return FALSE;
    }

    lpThreadFun = (LPTHREAD_START_ROUTINE) (SIZE_T) lpszRemoteBuf;

    hThread = CreateRemoteThread(hInjectProcess, NULL, 0, lpThreadFun, NULL, 0, NULL);
    if (!hThread)
    {
        hThread = OsCreateRemoteThread2(hInjectProcess, NULL, 0, lpThreadFun, NULL, 0, NULL);
    }
    if (!hThread)
    {
        VirtualFreeEx(hInjectProcess, lpszRemoteBuf, dwSize, MEM_DECOMMIT);
        CloseHandle(hInjectProcess);
        return FALSE;
    }

    NTSTATUS Status;
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, (DWORD*) &Status);

    VirtualFreeEx(hInjectProcess, lpszRemoteBuf, dwSize, MEM_DECOMMIT);
    CloseHandle(hThread);
    CloseHandle(hInjectProcess);

    return NT_SUCCESS(Status);
}

BOOL InjectRemoteCloseHandleByName(LPCWSTR lpszProcess, HANDLE hProcess, HANDLE hHandle)
{
    // Scan for a whitelisted process pid..
    DWORD MyTar = 0;
    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32 = { 0 };
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    pe32.dwSize = sizeof(pe32);
    if (Process32First(hProcessSnap, &pe32))
    {
        do
        {
            if (!lstrcmp(pe32.szExeFile, lpszProcess))
            {
                MyTar = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);

    return InjectRemoteCloseHandle(MyTar, hProcess, hHandle);
}

HANDLE SearchProcessHandle(DWORD ProcessId, SYSTEM_HANDLE_INFORMATION_EX* HandleInformation)
{
    CLIENT_ID cid;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;
    HANDLE hProcessGot;

    RtlZeroMemory(&oa, sizeof(oa));
    oa.Length = sizeof(oa);
    cid.UniqueProcess = (HANDLE) ProcessId;
    cid.UniqueThread = 0;
    Status = NtOpenProcess(&hProcessGot, PROCESS_ALL_ACCESS, &oa, &cid);
    if (NT_SUCCESS(Status))
    {
        return hProcessGot;
    }

    for (ULONG i = 0; i < HandleInformation->NumberOfHandles; i++)
    {
        if (ProcessTypeNumber == 0xFFFF)
        {
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD) HandleInformation->Handles[i].UniqueProcessId);
            HANDLE hObject = INVALID_HANDLE_VALUE;
            if (hProcess != NULL)
            {
                ZwDuplicateObject(hProcess, HandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hObject, PROCESS_QUERY_INFORMATION, 0, 0);
                if (hObject != INVALID_HANDLE_VALUE)
                {
                    OBJECT_BASIC_INFORMATION obi;
                    OBJECT_TYPE_INFORMATION* TypeInfo = NULL;
                    RtlZeroMemory(&obi, sizeof(OBJECT_BASIC_INFORMATION));
                    ZwQueryObject(hObject, ObjectBasicInformation, &obi, sizeof(obi), NULL);
                    if (obi.TypeInformationLength)
                    {
                        TypeInfo = (POBJECT_TYPE_INFORMATION) GlobalAlloc(GPTR, sizeof(BYTE) *(obi.TypeInformationLength * 2));
                        RtlZeroMemory(TypeInfo, obi.TypeInformationLength * 2);
                        Status = ZwQueryObject(hObject, ObjectTypeInformation, TypeInfo, obi.TypeInformationLength * 2, NULL);

                        if (!Mstrcmpn(TypeInfo->TypeName.Buffer, L"Process",
                            TypeInfo->TypeName.Length < 7 ? TypeInfo->TypeName.Length : 7))
                        {
                            ProcessTypeNumber = HandleInformation->Handles[i].ObjectTypeNumber;
                        }
                        GlobalFree(TypeInfo);
                    }
                    ZwClose(hObject);
                }
                CloseHandle(hProcess);
            }
        }
        if (HandleInformation->Handles[i].ObjectTypeNumber == ProcessTypeNumber)
        {
            HANDLE hProcessToDup;
            cid.UniqueProcess = HandleInformation->Handles[i].UniqueProcessId;
            Status = NtOpenProcess(&hProcessToDup, PROCESS_DUP_HANDLE, &oa, &cid);
            if (NT_SUCCESS(Status))
            {
                Status = ZwDuplicateObject(hProcessToDup, HandleInformation->Handles[i].HandleValue, (HANDLE) -1, &hProcessGot, PROCESS_ALL_ACCESS, 0, 0);
                if (NT_SUCCESS(Status))
                {
                    PROCESS_BASIC_INFORMATION pbi;
                    Status = ZwQueryInformationProcess(hProcessGot, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
                    if (NT_SUCCESS(Status))
                    {
                        if (ProcessId == pbi.UniqueProcessId)
                        {
                            ZwClose(hProcessToDup);
                            return hProcessGot;
                        }
                    }
                    ZwClose(hProcessGot);
                }
                ZwClose(hProcessToDup);
            }
        }
    }
    return NULL;
}

BOOL EnumerateAndCloseMutant(CLOSECALLBACK ShouldClose)
{
    ULONG BufLength = 0x100;
    LPBYTE OutBuffer = (LPBYTE) GlobalAlloc(GPTR, sizeof(BYTE) * BufLength);
    NTSTATUS Status;

    // it's strange, if we use the length value that returned in last parameter, we'll still get STATUS_INFO_LENGTH_MISMATCH.
    // maybe align? anyway we should guess it..  @ tested on Windows 7(6.1.7600.16385)
    do
    {
        BufLength *= 2;

        // Realloc 
        OutBuffer = (LPBYTE) GlobalReAlloc(OutBuffer, sizeof(BYTE) * BufLength, GMEM_MOVEABLE);
        RtlZeroMemory(OutBuffer, BufLength);

        Status = ZwQuerySystemInformation(SystemExtendedHandleInformation, OutBuffer, BufLength, NULL);
    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(Status))
    {
        return FALSE;
    }

    SYSTEM_HANDLE_INFORMATION_EX* HandleInformation = (PSYSTEM_HANDLE_INFORMATION_EX) OutBuffer;
    for (ULONG i = 0; i < HandleInformation->NumberOfHandles; i++)
    {
        // 搜索出一个MutantTypeNumber，比上面的GetObjectTypeNumber可靠
        if (MutantTypeNumber == 0xFFFF)
        {
            HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD) HandleInformation->Handles[i].UniqueProcessId);
            HANDLE hObject = INVALID_HANDLE_VALUE;
            if (hProcess != NULL)
            {
                ZwDuplicateObject(hProcess, HandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hObject, PROCESS_ALL_ACCESS, 0, 0);
                if (hObject != INVALID_HANDLE_VALUE)
                {
                    NTSTATUS Status;
                    OBJECT_BASIC_INFORMATION obi;
                    OBJECT_TYPE_INFORMATION* TypeInfo = NULL;
                    RtlZeroMemory(&obi, sizeof(OBJECT_BASIC_INFORMATION));
                    ZwQueryObject(hObject, ObjectBasicInformation, &obi, sizeof(obi), NULL);
                    if (obi.TypeInformationLength)
                    {
                        // Fix me : if we meet a NamedPipe or File Object before a Mutant.... we'll deadlock under XP or Vista!
                        TypeInfo = (POBJECT_TYPE_INFORMATION) GlobalAlloc(GPTR, sizeof(BYTE) * (obi.TypeInformationLength * 2));
                        RtlZeroMemory(TypeInfo, obi.TypeInformationLength * 2);
                        Status = ZwQueryObject(hObject, ObjectTypeInformation, TypeInfo, obi.TypeInformationLength * 2, NULL);

                        if (!Mstrcmpn(TypeInfo->TypeName.Buffer, L"Mutant",
                            TypeInfo->TypeName.Length < 6 ? TypeInfo->TypeName.Length : 6))
                        {
                            // Found!
                            MutantTypeNumber = HandleInformation->Handles[i].ObjectTypeNumber;
                        }
                        GlobalFree(TypeInfo);
                    }
                    ZwClose(hObject);
                }
                CloseHandle(hProcess);
            }
        }
        if (HandleInformation->Handles[i].ObjectTypeNumber == MutantTypeNumber)
        {
            HANDLE hProcess = SearchProcessHandle((DWORD) HandleInformation->Handles[i].UniqueProcessId, HandleInformation);
            if (!hProcess)
            {
                continue;
            }
            HANDLE hObject = INVALID_HANDLE_VALUE;
            ZwDuplicateObject(hProcess, HandleInformation->Handles[i].HandleValue, GetCurrentProcess(), &hObject, PROCESS_ALL_ACCESS, 0, 0);
            if (hObject == INVALID_HANDLE_VALUE)
            {
                continue;
            }

            NTSTATUS Status;
            OBJECT_BASIC_INFORMATION obi;
            OBJECT_TYPE_INFORMATION* TypeInfo = NULL;
            OBJECT_NAME_INFORMATION* NameInfo = NULL;
            RtlZeroMemory(&obi, sizeof(OBJECT_BASIC_INFORMATION));
            ZwQueryObject(hObject, ObjectBasicInformation, &obi, sizeof(obi), NULL);
            if (obi.TypeInformationLength)
            {
                TypeInfo = (POBJECT_TYPE_INFORMATION) GlobalAlloc(GPTR, sizeof(BYTE) * (obi.TypeInformationLength * 2));
                RtlZeroMemory(TypeInfo, obi.TypeInformationLength * 2);
                Status = ZwQueryObject(hObject, ObjectTypeInformation, TypeInfo, obi.TypeInformationLength * 2, NULL);
            }

            if (obi.NameInformationLength)
            {
                NameInfo = (POBJECT_NAME_INFORMATION) GlobalAlloc(GPTR, sizeof(BYTE) * (obi.NameInformationLength * 2));
                RtlZeroMemory(NameInfo, obi.NameInformationLength * 2);
                Status = ZwQueryObject(hObject, ObjectNameInformation, NameInfo, obi.NameInformationLength * 2, NULL);

                switch (ShouldClose(NameInfo->Name.Buffer, NameInfo->Name.Length))
                {
                    case CLOSE_DIRECT:
                    {
                        ZwClose(hObject);
                        hObject = INVALID_HANDLE_VALUE;
                        RemoteCloseHandle(hProcess, HandleInformation->Handles[i].HandleValue);
                        break;
                    }
                    case CLOSE_INJECT:
                    {
                        ZwClose(hObject);
                        hObject = INVALID_HANDLE_VALUE;
                        InjectRemoteCloseHandleByName(L"svchost.exe", hProcess, HandleInformation->Handles[i].HandleValue);
                        break;
                    }
                    default:
                        break;
                }
            }

            if (TypeInfo)
            {
                GlobalFree(TypeInfo);
            }
            if (NameInfo)
            {
                GlobalFree(NameInfo);
            }
            if (hObject != INVALID_HANDLE_VALUE)
            {
                ZwClose(hObject);
            }
            if (hProcess)
            {
                ZwClose(hProcess);
            }
        }
    }
    
    GlobalFree(OutBuffer);
    return TRUE;
}