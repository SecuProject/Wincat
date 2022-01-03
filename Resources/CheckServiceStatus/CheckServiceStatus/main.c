#include <windows.h>
#include <stdio.h>

#define SERVICE_ERROR		-1
#define SERVICE_NOT_RUNNING 0

INT ServerStatus(SC_HANDLE schService){
	SERVICE_STATUS_PROCESS ssStatus;
	DWORD dwBytesNeeded;
	if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)){
		switch (ssStatus.dwCurrentState){
		case SERVICE_START_PENDING:
		case SERVICE_CONTINUE_PENDING:
			printf("[*] The service is pending (Sleeping for 1 minute) !\n");
			Sleep(60 * 1000);
		case SERVICE_RUNNING:
			printf("[*] The service is running !\n");
			return TRUE;

		case SERVICE_STOPPED:
		case SERVICE_STOP_PENDING:
			printf("[x] The service is stopped !\n");
			break;
		case SERVICE_PAUSE_PENDING:
		case SERVICE_PAUSED:
			printf("[!] The service is paused !\n");
			break;
		default:
			printf("[!] The service status: %d\n", ssStatus.dwCurrentState);
			break;
		}
		return SERVICE_NOT_RUNNING;
	}
	printf("[!] QueryServiceStatusEx failed (%d)\n", GetLastError());
	return SERVICE_ERROR;
}

int CheckServerStatus(char* serviceName){
	SC_HANDLE schSCManager = OpenSCManagerA(NULL,NULL, GENERIC_READ);
	if (NULL != schSCManager){
		SC_HANDLE schService = OpenServiceA(schSCManager, serviceName, GENERIC_READ);
		if (schService != NULL){
			int retValue = ServerStatus(schService);
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return retValue;
		}else
			printf("[x] OpenService() failed, error: %d\n", GetLastError());
		CloseServiceHandle(schSCManager);
	}else
		printf("[x] OpenSCManager(), Open a handle to the SC Manager database failed, error: %d.\n", GetLastError());
	return SERVICE_ERROR;
}
int StartServer(char* serviceName){
	SC_HANDLE schSCManager = OpenSCManagerA(NULL, NULL, GENERIC_READ | GENERIC_EXECUTE);
	if (NULL != schSCManager){
		SC_HANDLE schService = OpenServiceA(schSCManager, serviceName, GENERIC_READ | GENERIC_EXECUTE);
		if (schService != NULL){
			if (StartServiceA(schService, 0, NULL)){
				printf("[i] Starting service %s...\n", serviceName);
				Sleep(100);
				int retValue = ServerStatus(schService);
				CloseServiceHandle(schService);
				CloseServiceHandle(schSCManager);
				return retValue;
			} else 
				printf("[x] StartService failed (%d)\n", GetLastError());
		} else
			printf("[x] OpenService() failed, error: %d\n", GetLastError());
		CloseServiceHandle(schSCManager);
	} else
		printf("[x] OpenSCManager(), Open a handle to the SC Manager database failed, error: %d.\n", GetLastError());
	return SERVICE_ERROR;
}

int main(DWORD argc, LPCTSTR* argv){
	char* serviceName = "Spooler";

	if (CheckServerStatus("Spooler") == SERVICE_NOT_RUNNING){
		StartServer(serviceName);
	}
	return 0;
}