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
