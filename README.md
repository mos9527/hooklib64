hooklib64
---
OOTB Windows x64 application hook framework based upon Skyth's https://github.com/blueskythlikesclouds/DivaModLoader

## Usage
Currently, the DLL can be spoofed as:
- winhttp.dll
- d3d9.dll
- d3d10.dll
- d3d11.dll
- xinput1_3.dll
- winhttp.dll
- version.dll

Identical files will be copied into the `artifacts/` directory. Copying those to applications that use them will allow the DLL to be loaded instead of the original.

## Examples
MSVC (Visual Studio) and CMake is required to compile the DLL due to the usage of `#pragma comment(lib, ...)`

### Win32 API Hooks
Hides the tray icon from the taskbar if the application creates one
```c++
#define HOOKLIB_MODULE_NAME NULL
#include "hooklib.hpp"

HOOKLIB_HOOK(BOOL, __stdcall, _Shell_NotifyIconA, &Shell_NotifyIconW, DWORD dwMessage, _In_ PNOTIFYICONDATAA lpData)
{	
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (HOOKLIB_IS_PROCESS(L"GameViewer.exe")) {
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
        {
#ifdef _DEBUG
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
#endif
            HOOKLIB_INSTALL_HOOK(_Shell_NotifyIconA);
            printf("All good.\n");
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
        }
    }    
    return TRUE;
}

```

### Signature Hooks
See https://github.com/mos9527/UnityUnsplash
```c++
#define HOOKLIB_MODULE_NAME L"UnityPlayer"
#include "hooklib.hpp"

SIG_SCAN
(
    sigSetSplashScreenState2019,
    0x180000000,
    "\x40\x56\x48\x83\xEC\x20\x48\x8B\x05\x00\x00\x00\x00\x8B\xF1\x39\x48\x08\x0F\x84\x00\x00\x00\x00\x48\x89\x5C\x24\x00\x48\x89\x7C\x24\x00\x89\x48\x08\xE8\x00\x00\x00\x00\x33\xFF\x48\x8D\x98\x00\x00\x00\x00\x8B\x80\x00\x00\x00\x00\x48\x89\x9B\x00\x00\x00\x00\x85\xC0\x74\x3D\x0F\x1F\x40\x00\x0F\x1F\x84\x00\x00\x00\x00\x00\x48\x8D\x0C\x7F\x48\x8B\x04\xCB\x48\x8D\x0C\xCB\x48\x85\xC0\x74\x14\x80\x79\x10\x00\x75\x06\x8B\xCE\xFF\xD0\xEB\x08",
    "xxxxxxxxx????xxxxxxx????xxxx?xxxx?xxxx????xxxxx????xx????xxx????xxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)
HOOK(void, __fastcall, _SetSplashScreenState, sigSetSplashScreenState2019(), int state) {
    LOG("SetSplashScreenState: %d", state);
    original_SetSplashScreenState(3); 
}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        INSTALL_HOOK(_RenderOverlays);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

### Helpers
Loading functions at runtime
```c++
#define HOOKLIB_MODULE_NAME NULL
#include <hooklib.hpp>
typedef struct {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
HOOKLIB_RUNTIME_FUNCTION(LONG, __cdecl, "ntdll.dll", NtRaiseHardError, LONG Status, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
HOOKLIB_RUNTIME_FUNCTION(LONG, __cdecl, "ntdll.dll", RtlSetProcessIsCritical, BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsWinlogon);
HOOKLIB_RUNTIME_FUNCTION(LONG, __cdecl, "ntdll.dll", RtlAdjustPrivilege, ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PULONG Enabled);
HOOKLIB_RUNTIME_FUNCTION(void, __cdecl, "ntdll.dll", RtlInitUnicodeString, UNICODE_STRING*, PCWSTR);
int main() {
	UNICODE_STRING uTitle, uText;
	RtlInitUnicodeString(&uTitle, L"NtRaiseHardError");
	RtlInitUnicodeString(&uText, L"Select [OK] to trigger OptionShutdownSystem. WARNING: This will in turn cause a BSOD!");
	ULONG_PTR args[] = { (ULONG_PTR)&uText, (ULONG_PTR)&uTitle, MB_OKCANCEL | MB_ICONWARNING };
	static ULONG resp;
	NtRaiseHardError(0x50000018, 3, 3, args, /* OptionOkCancel */ 3, &resp);
	if (resp == /* ResponseOk */ 6) {
		RtlAdjustPrivilege(19 /* SeDebugPrivilege */, TRUE, FALSE, &resp);
		NtRaiseHardError(0xDEAD9527, 0, 0, 0, /* OptionShutdownSystem */ 6, &resp);
	}
}
```

## Licesne
MIT