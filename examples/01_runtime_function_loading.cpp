// Loads kernel32.dll at runtime and then calls GetCurrentProcessId
#include <hooklib.hpp>

int main()
{
    HOOKLIB_RUNTIME_FUNCTION(DWORD, WINAPI, L"kernel32.dll", GetCurrentProcessId);
    if (!GetCurrentProcessId)
        return 1;
    std::printf("Current process: %lu\n", static_cast<unsigned long>(GetCurrentProcessId()));
    return 0;
}
