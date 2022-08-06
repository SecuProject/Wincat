#include <windows.h>
#include <stdio.h>

#include "Message.h"
#include "Tools.h"

#include "ProcessPrivilege.h"
#include "CheckCdpSvcLPE.h"
#include "EasyPrivEsc.h"
#include "loadAPI/LoadAPI.h"


BOOL IsAlwaysInstallElevated(Advapi32_API advapi32) {
	const char regKey[] = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
	const char value[] = "AlwaysInstallElevated";
	DWORD result = FALSE;

	if (ReadRegistryValue(advapi32, HKEY_LOCAL_MACHINE, (char*)regKey, (char*)value, (LPBYTE)&result, sizeof(DWORD))) {
		if (result) {
			printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Always Install Elevated is enable on the system !\n");
			return TRUE;
		}
	}
	return FALSE;
}	
		

EasyPriEsc EasyPrivEsc(Kernel32_API kernel32, Advapi32_API advapi32) {
	HANDLE hToken;
	EasyPriEsc easyPriEsc;

	printMsg(STATUS_TITLE, LEVEL_DEFAULT, "Checking for a easy way to Priv Esc\n");

	if (advapi32.OpenProcessTokenF(kernel32.GetCurrentProcessF(), TOKEN_ALL_ACCESS, &hToken)) {
		easyPriEsc.IsTokenService = IsTokenService(hToken);
		easyPriEsc.IsUserPrivilege = CheckUserPrivilege(hToken);
		kernel32.CloseHandleF(hToken);
	}else
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to OpenProcessToken");

	easyPriEsc.IsCdpSvcLPE = CheckCdpSvcLPE(kernel32, advapi32);
	easyPriEsc.IsAlwaysInstallElevated = IsAlwaysInstallElevated(advapi32);

	return easyPriEsc;
}