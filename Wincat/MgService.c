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