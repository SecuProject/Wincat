#include <windows.h>
#include <stdio.h>
#include "MgService.h"
#include "Message.h"



INT ServerStatus(SC_HANDLE schService){
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwBytesNeeded;
	if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)){
		switch (ssStatus.dwCurrentState){
		case SERVICE_START_PENDING:
		case SERVICE_CONTINUE_PENDING:
			printMsg(STATUS_OK2, LEVEL_DEFAULT, "The service is pending (Sleeping for 1 minute) !\n");
			Sleep(60 * 1000);
		case SERVICE_RUNNING:
			printMsg(STATUS_OK2, LEVEL_DEFAULT, "The service is running !\n");
			return TRUE;

		case SERVICE_STOPPED:
		case SERVICE_STOP_PENDING:
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "The service is stopped");
			break;
		case SERVICE_PAUSE_PENDING:
		case SERVICE_PAUSED:
			printMsg(STATUS_WARNING2, LEVEL_DEFAULT, "The service is paused !\n");
			break;
		default:
			printMsg(STATUS_WARNING2, LEVEL_DEFAULT, "The service status: %d\n", ssStatus.dwCurrentState);
			break;
		}
		return SERVICE_NOT_RUNNING;
	}
	printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "QueryServiceStatusEx failed");
	return SERVICE_ERROR;
}

int CheckServerStatus(char* serviceName){
	SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
	if (NULL != schSCManager){
		SC_HANDLE schService = OpenServiceA(schSCManager, serviceName, GENERIC_READ);
		if (schService != NULL){
			int retValue = ServerStatus(schService);
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return retValue;
		} else
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "OpenService() failed");
		CloseServiceHandle(schSCManager);
	} else
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "OpenSCManager(), Open a handle to the SC Manager database failed");
	return SERVICE_ERROR;
}
int StartServer(char* serviceName){
	SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ | GENERIC_EXECUTE);
	if (NULL != schSCManager){
		SC_HANDLE schService = OpenServiceA(schSCManager, serviceName, GENERIC_READ | GENERIC_EXECUTE);
		if (schService != NULL){
			if (StartServiceA(schService, 0, NULL)){
				printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Starting service %s...\n", serviceName);
				Sleep(100);
				int retValue = ServerStatus(schService);
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return retValue;
			} else
				printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "StartService failed");
		} else
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "OpenService() failed");
		CloseServiceHandle(schSCManager);
	} else
		printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "OpenSCManager(), Open a handle to the SC Manager database failed");
	return SERVICE_ERROR;
}

VOID PrintServiceType(DWORD dwServiceType) {
	printf("\tType:\t\t");
	switch (dwServiceType) {
	case SERVICE_FILE_SYSTEM_DRIVER:
		printf("FILE_SYSTEM_DRIVER");
		break;
	case SERVICE_KERNEL_DRIVER:
		printf("KERNEL_DRIVER");
		break;
	case SERVICE_WIN32_OWN_PROCESS:
		printf("WIN32_OWN_PROCESS");
		break;
	case SERVICE_WIN32_SHARE_PROCESS:
		printf("WIN32_SHARE_PROCESS");
		break;
	default:
		break;
	}
	printf(" (0x%x)\n", dwServiceType);
}
VOID PrintServiceStartType(DWORD dwStartType) {
	printf("\tStart Type:\t");
	switch (dwStartType) {
	case SERVICE_AUTO_START:
		printf("AUTO_START");
		break;
	case SERVICE_BOOT_START:
		printf("BOOT_START");
		break;
	case SERVICE_DEMAND_START:
		printf("DEMAND_START");
		break;
	case SERVICE_DISABLED:
		printf("DISABLED");
		break;
	case SERVICE_SYSTEM_START:
		printf("SYSTEM_START");
		break;
	default:
		break;
	}
	printf(" (0x%x)\n", dwStartType);
}
BOOL CheckServiceStatusConfig(char* szSvcName, BOOL isDebug) {
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	BOOL isAutoStart = FALSE;

	schSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (NULL == schSCManager) {
		printf("[x] OpenSCManager failed (%d)\n", GetLastError());
		return FALSE;
	}
	schService = OpenServiceA(schSCManager, szSvcName, SERVICE_QUERY_CONFIG);
	if (schService == NULL) {
		printf("[x] OpenService failed (%d)\n", GetLastError());
		CloseServiceHandle(schSCManager);
		return FALSE;
	}
	// Get the configuration information.
	LPQUERY_SERVICE_CONFIGA lpsc = NULL;
	DWORD dwBytesNeeded, cbBufSize, dwError;
	if (!QueryServiceConfigA(schService, NULL, 0, &dwBytesNeeded)) {
		dwError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwError) {
			cbBufSize = dwBytesNeeded;
			lpsc = (LPQUERY_SERVICE_CONFIGA)LocalAlloc(LMEM_FIXED, cbBufSize);
			if (lpsc != NULL && QueryServiceConfigA(schService, lpsc, cbBufSize, &dwBytesNeeded)) {
				if (isDebug) {
					printf("[i] %s configuration:\n", szSvcName);
					PrintServiceType(lpsc->dwServiceType);
					PrintServiceStartType(lpsc->dwStartType);
					//printf("\tError Control:\t0x%x\n", lpsc->dwErrorControl);
					printf("\tBinary path:\t%s\n", lpsc->lpBinaryPathName);
					printf("\tAccount:\t%s\n", lpsc->lpServiceStartName);
				}
				isAutoStart = lpsc->dwStartType & SERVICE_SYSTEM_START || lpsc->dwStartType & SERVICE_AUTO_START || lpsc->dwStartType & SERVICE_BOOT_START;
			}
			else
				printf("[x] QueryServiceConfig failed (%d)", GetLastError());

		}
		else {
			printf("[x] QueryServiceConfig failed (%d)", dwError);
		}
	}
	LocalFree(lpsc);

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return isAutoStart;
}