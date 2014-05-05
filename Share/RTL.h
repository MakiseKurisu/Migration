#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    int Mstrcmpn(LPCWSTR a, LPCWSTR b, int n);
    void * memset(void *, int, size_t);
#pragma intrinsic(memset)

#undef  RtlMoveMemory
    VOID WINAPI RtlMoveMemory(
        _In_    PVOID Destination,
        _In_    const VOID *Source,
        _In_    SIZE_T Length
        );

#undef  RtlCopyMemory
    VOID WINAPI RtlCopyMemory(
        _In_    PVOID Destination,
        _In_    const VOID *Source,
        _In_    SIZE_T Length
        );

#undef  RtlFillMemory
    VOID WINAPI RtlFillMemory(
        _Out_   PVOID Destination,
        _In_    SIZE_T Length,
        _In_    BYTE Fill
        );

#undef  RtlZeroMemory
    VOID WINAPI RtlZeroMemory(
        _In_    PVOID Destination,
        _In_    SIZE_T Length
        );

#ifdef __cplusplus
}
#endif