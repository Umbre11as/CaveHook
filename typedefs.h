#pragma once

#include <wtypes.h>

#ifndef QWORD
	typedef ULONGLONG QWORD;
#endif

#define HOOKCALLBACK __stdcall

struct ByteBuffer {
    BYTE* Buffer;
    SIZE_T Length;
};

typedef struct HOOK_DATA_ {
    QWORD Target;
    LPVOID Detour;
    LPVOID Trampoline;
    ByteBuffer Prologue;
} HOOK_DATA, *PHOOK_DATA, *LPHOOK_DATA;
