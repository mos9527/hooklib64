// Hooks ShellNotifyIconW Win32 API in in GameViewer.exe
#include <hooklib.hpp>
#include <shellapi.h>

HOOKLIB_DECL_HOOK(BOOL, WINAPI, ShellNotifyIconW, DWORD message, PNOTIFYICONDATAW data);

BOOL WINAPI implOfShellNotifyIconW(DWORD message, PNOTIFYICONDATAW data)
{
    return TRUE;
}

extern "C" __declspec(dllexport) LONG WINAPI HooklibInitialize()
{
    if (!HOOKLIB_IS_PROCESS(L"GameViewer.exe"))
        return ERROR_NOT_SUPPORTED;
    const LONG error = HOOKLIB_RESOLVE_HOOK(ShellNotifyIconW, &Shell_NotifyIconW);
    if (error != NO_ERROR && error != ERROR_ALREADY_EXISTS)
        return error;
    return HOOKLIB_INSTALL_HOOK(ShellNotifyIconW);
}
