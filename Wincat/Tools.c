#include <Windows.h>
#include <stdio.h>

#include "Message.h"

///////////////////////// Registry //////////////////////////
//

BOOL ReadRegistryValue(HKEY key, char* path, char* name, LPBYTE valueOutput, DWORD valueOutputSize) {
	BOOL returnValue = FALSE;
	HKEY hKey;
	if (RegOpenKeyExA(key, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegQueryValueExA(hKey, name, 0, NULL, valueOutput, &valueOutputSize) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;
}

BOOL checkKey(const char* subKeyTab) {
	HKEY hKey;
	long regKey = RegOpenKeyExA(HKEY_CURRENT_USER, subKeyTab, 0, KEY_QUERY_VALUE, &hKey);
	if (ERROR_FILE_NOT_FOUND == regKey) {
		printMsg(STATUS_INFO, LEVEL_VERBOSE, "Creating registry key %s\n", subKeyTab);
		if (RegCreateKeyExA(HKEY_CURRENT_USER, subKeyTab, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Critical fail RegCreateKeyExA");
			return FALSE;
		}
	}
	RegCloseKey(hKey);
	return 1;
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

	/*BOOL returnValue = !ERROR_SUCCESS;
	HKEY hKey;
	if (RegOpenKeyExA(key, path, 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS && hKey != NULL) {
		returnValue = RegDeleteKeyA(hKey, name) == ERROR_SUCCESS;
		RegCloseKey(hKey);
	}
	return returnValue;*/
}

BOOL isArgHostSet() {
	BOOL result = FALSE;
	DWORD RHostIPaddressSize = 128;
	char* RHostIPaddress = (char*)calloc(RHostIPaddressSize, 1);
	if (RHostIPaddress != NULL) {
		result = ReadRegistryValue(HKEY_CURRENT_USER, "Software\\Wincat", "RHostIP", RHostIPaddress, RHostIPaddressSize);
		result &= ReadRegistryValue(HKEY_CURRENT_USER, "Software\\Wincat", "RHostPORT", RHostIPaddress, RHostIPaddressSize);
		free(RHostIPaddress);
	}
	return result;
}
//
///////////////////////// Registry //////////////////////////


//////////////////// Windows Redirection ////////////////////
//

void DisableWindowsRedirection(PVOID* pOldVal) {
	Wow64DisableWow64FsRedirection(pOldVal);
	/*if (!Wow64DisableWow64FsRedirection(pOldVal))
		printf("\t[X] Wow64DisableWow64FsRedirection Failed !!!\n");*/
}
void RevertWindowsRedirection(PVOID pOldVal) {
	Wow64RevertWow64FsRedirection(pOldVal);
	/*if (!Wow64RevertWow64FsRedirection(pOldVal))
		printf("\t[X] Wow64RevertWow64FsRedirection Failed !!!\n");*/
}

//
//////////////////// Windows Redirection ////////////////////


////////////////////// Execute Process //////////////////////
//

BOOL RunAs(char* executablePath, char* lpParameters) {
	SHELLEXECUTEINFOA ShRun = { 0 };
	ShRun.cbSize = sizeof(SHELLEXECUTEINFOA);
	ShRun.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShRun.hwnd = NULL;
	ShRun.lpVerb = "runas";
	ShRun.lpFile = executablePath;
	ShRun.lpParameters = lpParameters;
	ShRun.lpDirectory = NULL;
	ShRun.nShow = SW_HIDE;
	ShRun.hInstApp = NULL;
	return ShellExecuteExA(&ShRun);
}
BOOL Run(char* executablePath, char* lpParameters) {
	SHELLEXECUTEINFOA ShRun = { 0 };
	ShRun.cbSize = sizeof(SHELLEXECUTEINFOA);
	ShRun.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShRun.hwnd = NULL;
	ShRun.lpFile = executablePath;
	ShRun.lpParameters = lpParameters;
	ShRun.lpDirectory = NULL;
	ShRun.nShow = SW_HIDE;
	ShRun.hInstApp = NULL;
	return ShellExecuteExA(&ShRun);
}

// 
////////////////////// Execute Process //////////////////////


BOOL IsFileExist(char* filePath) {
	FILE* pFile;
	if (fopen_s(&pFile, filePath, "r") == 0 && pFile != NULL) {
		fclose(pFile);
		return TRUE;
	}
	return FALSE;
}

void gen_random(char* string, const int len) {
	char alphanum[63];
	int ich = 0;
	for (char l = 'a'; l <= 'z'; ++l, ich++)
		alphanum[ich] = l;
	for (char l = 'A'; l <= 'Z'; ++l, ich++)
		alphanum[ich] = l;
	for (char l = '0'; l <= '9'; ++l, ich++)
		alphanum[ich] = l;


	for (int i = 0; i < len; ++i)
		string[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	string[len] = 0;
}



VOID ToLower(char* str1, size_t sizeStr1, char* str2){
	for (size_t i = 0; i < sizeStr1; i++)
		str2[i] = tolower(str1[i]);
	str2[sizeStr1] = 0x00;
}
BOOL CheckStrMatch(char* str1, const char* str2) {
	BOOL returnVal = FALSE;
	size_t sizeStr1 = strlen(str1);

	char* temp1 = (char*)malloc(sizeStr1 + 1);
	if (temp1 != NULL) {
		ToLower(str1, sizeStr1, temp1);
		returnVal = strstr(temp1, str2) != NULL;
		free(temp1);
	}
	return returnVal;
}