// Hides the Unity splash screen in a Unity 2019 x64 Player Build with a custom IDA signature
// Use https://github.com/kweatherman/sigmakerex to generate the sigs.
#define HOOKLIB_MODULE_NAME L"UnityPlayer"
#include <hooklib.hpp>

HOOKLIB_SIG_DECL
(
    sigSetSplashScreenState2019,
    0x180000000,
    "\x40\x56\x48\x83\xEC\x20\x48\x8B\x05\x00\x00\x00\x00\x8B\xF1\x39\x48\x08\x0F\x84\x00\x00\x00\x00\x48\x89\x5C\x24\x00\x48\x89\x7C\x24\x00\x89\x48\x08\xE8\x00\x00\x00\x00\x33\xFF\x48\x8D\x98\x00\x00\x00\x00\x8B\x80\x00\x00\x00\x00\x48\x89\x9B\x00\x00\x00\x00\x85\xC0\x74\x3D\x0F\x1F\x40\x00\x0F\x1F\x84\x00\x00\x00\x00\x00\x48\x8D\x0C\x7F\x48\x8B\x04\xCB\x48\x8D\x0C\xCB\x48\x85\xC0\x74\x14\x80\x79\x10\x00\x75\x06\x8B\xCE\xFF\xD0\xEB\x08",
    "xxxxxxxxx????xxxxxxx????xxxx?xxxx?xxxx????xxxxx????xx????xxx????xxxxxxxxxxxx????xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)

HOOKLIB_HOOK(void, __fastcall, _SetSplashScreenState, sigSetSplashScreenState2019(), int state)
{
    HOOKLIB_LOG("SetSplashScreenState: %d", state);
    original_SetSplashScreenState(3);
}

extern "C" __declspec(dllexport) LONG WINAPI HooklibInitialize()
{
    if (!HOOKLIB_SIG_SCAN(sigSetSplashScreenState2019))
        return static_cast<LONG>(GetLastError());
    return HOOKLIB_INSTALL_HOOK(_SetSplashScreenState);
}
