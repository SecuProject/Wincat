#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>


BOOL IsWindowsVistaOrGreater() {
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = HIBYTE(_WIN32_WINNT_VISTA);
	osvi.dwMinorVersion = LOBYTE(_WIN32_WINNT_VISTA);
	osvi.wServicePackMajor = 0;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}

BOOL IsRunAsAdmin() {
	BOOL  fIsRunAsAdmin = FALSE;
	PSID  pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
		if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
			FreeSid(pAdministratorsGroup);
			return fIsRunAsAdmin;
		}
		FreeSid(pAdministratorsGroup);
	}
	return fIsRunAsAdmin;
}

BOOL IsUserInAdminGroup() {
	BOOL   fInAdminGroup = FALSE;
	DWORD  dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hTokenToCheck = NULL;
	DWORD  cbSize = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
		dwError = GetLastError();
		goto Cleanup;
	}

	if (IsWindowsVistaOrGreater()) {
		TOKEN_ELEVATION_TYPE elevType;
		if (!GetTokenInformation(hToken, TokenElevationType, &elevType, sizeof(elevType), &cbSize)) {
			dwError = GetLastError();
			goto Cleanup;
		}
		if (TokenElevationTypeLimited == elevType) {
			if (!GetTokenInformation(hToken, TokenLinkedToken, &hTokenToCheck, sizeof(hTokenToCheck), &cbSize)) {
				dwError = GetLastError();
				goto Cleanup;
			}
		}
	}
	if (!hTokenToCheck) {
		if (!DuplicateToken(hToken, SecurityIdentification, &hTokenToCheck)) {
			dwError = GetLastError();
			goto Cleanup;
		}
	}

	BYTE adminSID[SECURITY_MAX_SID_SIZE];
	cbSize = sizeof(adminSID);
	if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &cbSize)) {
		dwError = GetLastError();
		goto Cleanup;
	}

	if (!CheckTokenMembership(hTokenToCheck, &adminSID, &fInAdminGroup)) {
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	if (hToken) {
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (hTokenToCheck) {
		CloseHandle(hTokenToCheck);
		hTokenToCheck = NULL;
	}

	if (ERROR_SUCCESS != dwError) {
		printf("Fail %i\n", dwError);
		return FALSE;
	}

	return fInAdminGroup;
}

BOOL EnableWindowsPrivilege(LPCWSTR Privilege) {
	/* Tries to enable privilege if it is present to the Permissions set. */
	LUID luid;
	TOKEN_PRIVILEGES tp;
	HANDLE currentProcess = GetCurrentProcess();
	HANDLE currentToken;

	if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) return FALSE;
	return TRUE;
}



BOOL CheckWindowsPrivilege(LPCWSTR Privilege) {
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;
	hProcess = GetCurrentProcess();
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return FALSE;
	if (!LookupPrivilegeValueW(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

HANDLE GetAccessToken(DWORD pid) {

	/* Retrieves an access token for a process */
	HANDLE currentProcess;
	HANDLE AccessToken;
	DWORD LastError;

	if (pid == 0) {
		currentProcess = GetCurrentProcess();
	} else {
		currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (!currentProcess) {
			LastError = GetLastError();
			printf("ERROR: OpenProcess(): %ld\n", LastError);
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken)) {
		LastError = GetLastError();
		printf("ERROR: OpenProcessToken(): %ld\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}

int GetTargetProcessPID(WCHAR* processName) {
	HANDLE snap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snap == INVALID_HANDLE_VALUE) {
		printf("CreateToolhelp32Snapshot() Failed.");
		return FALSE;
	}

	if (!Process32First(snap, &pe32)) {
		printf("Process32First() Failed.");
		return FALSE;
	}

	while (0 != wcsncmp(processName, pe32.szExeFile, wcslen(processName)) && Process32Next(snap, &pe32));
	if (0 != wcsncmp(processName, pe32.szExeFile, wcslen(processName)))
		printf("No infomation found about \"%ws\"\n", processName);
	else {
		printf("Program name:%ws\nProcess id: %d\n", pe32.szExeFile, pe32.th32ProcessID);
		CloseHandle(snap);
		return pe32.th32ProcessID;
	}
	CloseHandle(snap);
	return FALSE;
}

