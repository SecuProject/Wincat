#include <windows.h>
#include <stdio.h>

#include "Message.h"
#include "Tools.h"

#include "ProcessPrivilege.h"
#include "CheckCdpSvcLPE.h"

typedef struct {
	BOOL IsAlwaysInstallElevated;
	BOOL IsCdpSvcLPE;
	BOOL IsUserPrivilege;
	BOOL IsTokenService;
}EasyPriEsc;

BOOL IsAlwaysInstallElevated() {
	const char regKey[] = "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer";
	const char value[] = "AlwaysInstallElevated";
	DWORD result = FALSE;

	if (ReadRegistryValue(HKEY_LOCAL_MACHINE, (char*)regKey, (char*)value, (LPBYTE)&result, sizeof(DWORD))) {
		if (result) {
			printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Always Install Elevated is enable on the system !\n");
			return TRUE;
		}
	}
	return FALSE;
}


BOOL EasyPrivEsc() {
	HANDLE hToken;
	EasyPriEsc easyPriEsc;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to OpenProcessToken");
		return FALSE;
	}

	easyPriEsc.IsTokenService = IsTokenService(hToken);
	easyPriEsc.IsUserPrivilege = CheckUserPrivilege(hToken);
	easyPriEsc.IsCdpSvcLPE = CheckCdpSvcLPE();
	easyPriEsc.IsAlwaysInstallElevated = IsAlwaysInstallElevated();

	CloseHandle(hToken);
	return TRUE;
}