#include <Windows.h>
#include <stdio.h>

#include "Message.h"
#include "MgService.h"
#include "Tools.h"

#define DEFAULT_BUFFER_SIZE 1024 * 4
#define MAX_NB_PATH 50

BOOL GetSystemEnvPath(char*** pppListEnvPath, UINT* pNbEnvPath) {
	BOOL result = FALSE;

	UINT nbEnvPath = 0;
	char** ppListEnvPath = (char**)calloc(MAX_NB_PATH, sizeof(char*));
	if (ppListEnvPath == NULL)
		return FALSE;

	char* tempBuffer = (char*)malloc(DEFAULT_BUFFER_SIZE);
	if (tempBuffer == NULL)
		return FALSE;

	result = ReadRegistryValue(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Session Manager\\Environment", "PATH", tempBuffer, DEFAULT_BUFFER_SIZE);

	if (result) {
		char* next_token = NULL;
		char* token = strtok_s(tempBuffer, ";", &next_token);
		for (nbEnvPath = 0; token && nbEnvPath < MAX_NB_PATH; nbEnvPath++) {
			size_t strLen = strlen(token) + 1;
			ppListEnvPath[nbEnvPath] = (char*)malloc(strLen);
			if (ppListEnvPath[nbEnvPath] == NULL)
				return FALSE;
			strcpy_s(ppListEnvPath[nbEnvPath], strLen, token);
			token = strtok_s(NULL, ";", &next_token);
		}
	}
	free(tempBuffer);
	*pppListEnvPath = realloc(ppListEnvPath, sizeof(char*) * nbEnvPath);
	*pNbEnvPath = nbEnvPath;
	return TRUE;
}

BOOL CheckWriteAccess(char* directory) {
	char* filePath = (char*)malloc(MAX_PATH);
	if (filePath != NULL) {
		sprintf_s(filePath, MAX_PATH, "%s\\frzyufezuy.txt", directory);

		HANDLE hFile = CreateFileA(filePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
			DeleteFileA(filePath);
			free(filePath);
			return TRUE;
		}
		free(filePath);
	}
	return FALSE;
}

BOOL CheckCdpSvcLPE() {
	char** listEnvPath;
	UINT nbEnvPath = 0;

	if (!CheckServiceStatusConfig((char*)"CDPSvc", FALSE)) {
		printMsg(STATUS_TITLE, LEVEL_VERBOSE, "Windows Local Privilege Escalation via CdpSvc\n");
		printMsg(STATUS_ERROR2, LEVEL_VERBOSE, "Service CdpSvc is disable !\n");
		return FALSE;
	}


	if (GetSystemEnvPath(&listEnvPath, &nbEnvPath) && nbEnvPath > 0) {
		for (UINT i = 0; i < nbEnvPath; i++) {
			if (CheckWriteAccess(listEnvPath[i])) {
				printMsg(STATUS_TITLE, LEVEL_DEFAULT,	"Windows Local Privilege Escalation via CdpSvc\n");
				printMsg(STATUS_OK2, LEVEL_DEFAULT,		"Service CdpSvc is enable !\n");
				printMsg(STATUS_OK2, LEVEL_DEFAULT,		"Directory %s is writable by the current user !\n", listEnvPath[i]);
				printMsg(STATUS_INFO2, LEVEL_DEFAULT,	"Try to drop %s\\cdpsgshims.dll\n", listEnvPath[i]);
				free(listEnvPath);
				return TRUE;
			}
		}
		free(listEnvPath);
	}
	return FALSE;
}