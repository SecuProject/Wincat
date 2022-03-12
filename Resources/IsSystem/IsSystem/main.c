#include <windows.h>
#include <stdio.h>
#include <Lmcons.h>

BOOL IsSystem(){
	char* userName = (char*)malloc(UNLEN + 1);
	if (userName != NULL){
		DWORD bufferSize = UNLEN + 1;
		if (GetUserNameA(userName,&bufferSize)){
			printf("[i] USERNAME: %s\n", userName);
			if (strcmp(userName,"SYSTEM") == 0){
				printf("[*] IsSystem !!!\n");
				free(userName);
				return TRUE;
			}
		}
		free(userName);
	}
	return FALSE;
}


typedef enum{
	LEVEL_LOW,
	LEVEL_MEDIUM,
	LEVEL_HIGH,
	LEVEL_SYSTEM,
	LEVEL_ERROR = -1,
}IntegrityLevel;


IntegrityLevel GetProcessIntegrityLevel(HANDLE hProcess){
    HANDLE hToken;
	IntegrityLevel integrityLevel  = LEVEL_ERROR;

	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)){
		DWORD cbTokenIL = 0;
		PTOKEN_MANDATORY_LABEL pTokenIL = NULL;

		GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);

		pTokenIL = (TOKEN_MANDATORY_LABEL*)malloc(cbTokenIL);
		if (pTokenIL != NULL){
			if (GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL)){
				PDWORD pDwIntegrityLevel = GetSidSubAuthority(pTokenIL->Label.Sid, 0);
				if (pDwIntegrityLevel != NULL){
					if (*pDwIntegrityLevel == SECURITY_MANDATORY_LOW_RID){
						integrityLevel = LEVEL_LOW;
					} else if (*pDwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && *pDwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID){
						integrityLevel = LEVEL_MEDIUM;
					} else if (*pDwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID && *pDwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID){
						integrityLevel = LEVEL_HIGH;
					} else if (*pDwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID){
						integrityLevel = LEVEL_SYSTEM;
					}
				}
			}
			free(pTokenIL);
		}
		CloseHandle(hToken);

	}
	return integrityLevel;
}




int main(){
	if(IsSystem())
		printf("[*] IsSystem !!!\n");
	else
		printf("[*] User !!!\n");


	if(GetProcessIntegrityLevel(GetCurrentProcess()) == LEVEL_SYSTEM)
		printf("[*] IsSystem !!!\n");
	else
		printf("[*] User !!!\n");

	system("pause");
	return FALSE;
}