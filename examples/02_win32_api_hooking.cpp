// Hooks ShellNotifyIconW Win32 API in in GameViewer.exe
#include <hooklib.hpp>
#include <shellapi.h>

HOOKLIB_DECL_HOOK(BOOL, WINAPI, ShellNotifyIconW, DWORD message, PNOTIFYICONDATAW data);

BOOL WINAPI implOfShellNotifyIconW(DWORD message, PNOTIFYICONDATAW data)
{
    return TRUE;
}

// Declare DLLMain with this macro with a new thread, and defines the `HooklibInitialize()` C export.
//
// This is meant for avoiding global deadlocks (e.g. LoadLibrary gets called here *again*)
// - Obligatory Raymond Chen article: https://devblogs.microsoft.com/oldnewthing/20040128-00/?p=40853/
//
// For otherwise trivial DLLMain, use HOOKLIB_DLLMAIN, which does so in-place.
HOOKLIB_DLLMAIN_ASYNC()
{
    if (!HOOKLIB_IS_PROCESS(L"GameViewer.exe"))
        return ERROR_NOT_SUPPORTED;
    const LONG error = HOOKLIB_RESOLVE_HOOK(ShellNotifyIconW, &Shell_NotifyIconW);
    if (error != NO_ERROR && error != ERROR_ALREADY_EXISTS)
        return error;
    return HOOKLIB_INSTALL_HOOK(ShellNotifyIconW);
}
