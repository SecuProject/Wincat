#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Lmcons.h>
#include <sddl.h>

#include "Message.h"
#include "CheckSystem.h"
#include "Tools.h"

#include "LoadAPI.h"

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

BOOL IsRunAsSystem(){
	char* userName = (char*)malloc(UNLEN + 1);
	if (userName != NULL){
		DWORD bufferSize = UNLEN + 1;
		if (GetUserNameA(userName, &bufferSize)){
			if (strcmp(userName, "SYSTEM") == 0){
				printMsg(STATUS_OK2, LEVEL_VERBOSE, "Running as SYSTEM !!!\n");
				free(userName);
				return TRUE;
			}
		}
		free(userName);
	}
	return FALSE;
}

BOOL IsRunAsAdmin(Advapi32_API advapi32Api) {
	BOOL  fIsRunAsAdmin = FALSE;
	PSID  pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (advapi32Api.AllocateAndInitializeSidF(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)) {
		if (!advapi32Api.CheckTokenMembershipF(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
			advapi32Api.FreeSidF(pAdministratorsGroup);
			return fIsRunAsAdmin;
		}
		advapi32Api.FreeSidF(pAdministratorsGroup);
	}
	return fIsRunAsAdmin;
}

BOOL IsUserInAdminGroup() {
	BOOL   fInAdminGroup = FALSE;
	//DWORD  dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hTokenToCheck = NULL;
	DWORD  cbSize = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: OpenProcessToken");
		return FALSE;
	}

	if (IsWindowsVistaOrGreater()) {
		TOKEN_ELEVATION_TYPE elevType;
		if (!GetTokenInformation(hToken, TokenElevationType, &elevType, sizeof(elevType), &cbSize)) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: GetTokenInformation");
			CloseHandle(hToken);
			return FALSE;
		}
		if (TokenElevationTypeLimited == elevType) {
			if (!GetTokenInformation(hToken, TokenLinkedToken, &hTokenToCheck, sizeof(hTokenToCheck), &cbSize)) {
				printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: GetTokenInformation");
				CloseHandle(hToken);
				return FALSE;
			}
		}
		if (!hTokenToCheck) {
			if (!DuplicateToken(hToken, SecurityIdentification, &hTokenToCheck)) {
				printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: DuplicateToken");
				CloseHandle(hTokenToCheck);
				CloseHandle(hToken);
				return FALSE;
			}
		}

		BYTE adminSID[SECURITY_MAX_SID_SIZE];
		cbSize = sizeof(adminSID);
		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &cbSize)) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: CreateWellKnownSid");
			CloseHandle(hTokenToCheck);
			CloseHandle(hToken);
			return FALSE;
		}

		if (!CheckTokenMembership(hTokenToCheck, &adminSID, &fInAdminGroup)) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: CheckTokenMembership");
			CloseHandle(hTokenToCheck);
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hTokenToCheck);
	}
	CloseHandle(hToken);
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

	if (!OpenProcessToken(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) 
		return FALSE;
	if (!AdjustTokenPrivileges(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) 
		return FALSE;
	return TRUE;
}


BOOL IsUserPrivilegeEnable(HANDLE hToken, char* priv) {
	LUID luid;
	BOOL bRes;
	PRIVILEGE_SET tokPrivSet;

	if (!LookupPrivilegeValueA(NULL, priv, &luid)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: LookupPrivilegeValue %s", priv);
		return FALSE;
	}

	tokPrivSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	tokPrivSet.PrivilegeCount = 1;
	tokPrivSet.Privilege[0].Luid = luid;
	tokPrivSet.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!PrivilegeCheck(hToken, &tokPrivSet, &bRes)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: PrivilegeCheck");
		return FALSE;
	}
	return bRes;
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

	if (pid == 0)
		currentProcess = GetCurrentProcess();
	else {
		currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (!currentProcess) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: OpenProcess");
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: OpenProcessToken");
		CloseHandle(currentProcess);
		return (HANDLE)NULL;
	}
	CloseHandle(currentProcess);
	return AccessToken;
}
BOOL GetAccountInformation(HANDLE hToken, PAccountInformation* ppAccountInformation) {
	DWORD tokenSize = 0;
	TOKEN_USER* User;
	BOOL isCleanToken = FALSE;

	if (hToken == NULL) {
		hToken = GetAccessToken(0);
		if (hToken == NULL)
			return FALSE;
		isCleanToken = TRUE;
	}

	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenSize)) {
		DWORD dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: GetTokenInformation");
			if (isCleanToken)
				CloseHandle(hToken);
			return FALSE;
		}
	}
	User = (TOKEN_USER*)malloc(tokenSize);
	if (User != NULL) {
		if (GetTokenInformation(hToken, TokenUser, User, tokenSize, &tokenSize)) {
			SID_NAME_USE SidType;
			DWORD UserSize = MAX_NAME, DomainSize = MAX_NAME;
			PAccountInformation pAccountInformation = (PAccountInformation)malloc(sizeof(AccountInformation));
			if (pAccountInformation == NULL) {
				printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to alloc PAccountInformation");
				free(User);
				if (isCleanToken)
					CloseHandle(hToken);
				return FALSE;
			}


			if (LookupAccountSidA(NULL, User->User.Sid, pAccountInformation->UserName, &UserSize, pAccountInformation->DomainName, &DomainSize, &SidType)) {
				LPSTR lpSID = NULL;

				if (ConvertSidToStringSidA(User->User.Sid, &lpSID)) {
					strcpy_s(pAccountInformation->SID, MAX_NAME, lpSID);
					LocalFree(lpSID);
				}
				else
					strcpy_s(pAccountInformation->SID, MAX_NAME, "N/A");

				free(User);
				*ppAccountInformation = pAccountInformation;
				if (isCleanToken)
					CloseHandle(hToken);
				return TRUE;

			}
			else
				printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: LookupAccountSidA");
			free(pAccountInformation);
		}else
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: GetTokenInformation");
		free(User);
	}
	return FALSE;
}


int GetTargetProcessPID(WCHAR* processName) {
	HANDLE snap;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snap == INVALID_HANDLE_VALUE) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: CreateToolhelp32Snapshot");
		return FALSE;
	}

	if (!Process32FirstW(snap, &pe32)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: Process32First");
		CloseHandle(snap);
		return FALSE;
	}

	while (0 != wcsncmp(processName, pe32.szExeFile, wcslen(processName)) && Process32NextW(snap, &pe32));
	if (0 != wcsncmp(processName, pe32.szExeFile, wcslen(processName)))
		printMsg(STATUS_WARNING, LEVEL_DEFAULT, "No infomation found about \"%ws\"\n", processName);
	else {
		printMsg(STATUS_OK, LEVEL_DEFAULT, "Program name: %ws (PID: %d)\n", pe32.szExeFile, pe32.th32ProcessID);
		CloseHandle(snap);
		return pe32.th32ProcessID;
	}
	CloseHandle(snap);
	return FALSE;
}



BOOL IsUACEnabled(Advapi32_API advapi32) {
	BOOL dwValue = FALSE;
	DWORD dwSize = sizeof(DWORD);
	if (!ReadRegistryValue(advapi32, HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", (char*)&dwValue, dwSize)) {

		//if (!ReadRegKeyBOOL(HKEY_LOCAL_MACHINE, &dwValue)) { // "EnableLUA"*/
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to read 'EnableLUA' regkey");
		return TRUE; // IF Fail we will estimate that the UAC is enabled
	}
	return dwValue; // Return 1 if the UAC is enabled
}
UAC_POLICY CheckUACSettings(Advapi32_API advapi32) {
	DWORD consentPromptBehaviorAdmin = 0;
	DWORD secureDesktopPrompt = 0;
	DWORD dwSize = sizeof(DWORD);

	if (!ReadRegistryValue(advapi32,HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin", (LPBYTE)&consentPromptBehaviorAdmin, dwSize)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to read 'ConsentPromptBehaviorAdmin' regkey");
		return UAC_POLICY_ERROR;
	}
	if (!ReadRegistryValue(advapi32,HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "PromptOnSecureDesktop", (LPBYTE)&secureDesktopPrompt, dwSize)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to read 'SecureDesktopPrompt' regkey");
		return UAC_POLICY_ERROR;
	}
	/*
	consentPromptBehaviorAdmin:
	0 = Elevate without prompting
	1 = Prompt for credentials on the secure desktop
	2 = Prompt for consent on the secure desktop
	3 = Prompt for credentials
	4 = Prompt for consent
	5 = Prompt for consent for non-Windows binaries (default)
	*/

	if (consentPromptBehaviorAdmin == 2 && secureDesktopPrompt == 1) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "UAC is set to 'Always Notify'. This module does not bypass this setting");
		return UAC_POLICY_ALWAYS_NOTIFY;
	} else if (consentPromptBehaviorAdmin == 5 && secureDesktopPrompt == 1) {
		return UAC_POLICY_DEFAULT;
	} else if (consentPromptBehaviorAdmin == 0) {
		return UAC_POLICY_DISABLE;
	}
	return UAC_POLICY_DEFAULT; // OK ??? 
}