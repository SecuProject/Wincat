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



int main(){
	IsSystem();
	system("pause");
	return FALSE;
}