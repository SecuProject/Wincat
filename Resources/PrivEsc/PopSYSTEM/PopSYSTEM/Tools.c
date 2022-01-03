#include <Windows.h>
#include <stdio.h>

BOOL ReadRegistryValue(HKEY key, char* path, char* name, char* valueOutput, DWORD RHostPortSize) {
	BOOL returnValue = FALSE;
	HKEY hKey;
	if (RegOpenKeyExA(key, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegQueryValueExA(hKey, name, 0, NULL, (LPBYTE)valueOutput, &RHostPortSize) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;
}

BOOL checkKey(const char* subKeyTab) {
	HKEY hKey;
	long regKey = RegOpenKeyExA(HKEY_CURRENT_USER, subKeyTab, 0, KEY_QUERY_VALUE, &hKey);
	if (ERROR_FILE_NOT_FOUND == regKey) {
		printf("\t[i] Creating registry key %s\n", subKeyTab);
		if (RegCreateKeyExA(HKEY_CURRENT_USER, subKeyTab, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			printf("\t[X] Critical fail %ld ! (RegCreateKeyExA)\n", GetLastError());
			return FALSE;
		}
	}
	RegCloseKey(hKey);
	return 1;
}

BOOL SetRegistryValue(HKEY key, char* path, char* name, char* value) {
	BOOL returnValue = FALSE;
	HKEY hKey;
	if (RegOpenKeyExA(key, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegSetValueExA(hKey, name, 0, REG_SZ, (LPBYTE)value, strlen(value)) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;
}

BOOL DeleteRegistryKey(HKEY key, char* path, char* name) {
	BOOL returnValue = FALSE;
	HKEY hKey;
	if (RegOpenKeyExA(key, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegDeleteKeyA(hKey, name) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;
}

void DisableWindowsRedirection(PVOID* pOldVal) {
	if (!Wow64DisableWow64FsRedirection(pOldVal))
		printf("\t[X] Wow64DisableWow64FsRedirection Failed !!!\n");
}
void RevertWindowsRedirection(PVOID pOldVal) {
	if (!Wow64RevertWow64FsRedirection(pOldVal))
		printf("\t[X] Wow64RevertWow64FsRedirection Failed !!!\n");
}
