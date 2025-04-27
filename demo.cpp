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