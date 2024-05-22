#pragma once

#include "typedefs.h"
#include "Errors.h"

__declspec(dllexport) bool CaveHookEx(QWORD target, LPVOID detour, LPVOID* original, HOOK_DATA* hookData);
__declspec(dllexport) bool CaveHook(QWORD target, LPVOID detour, LPVOID* original);
int CaveLastError();
