#include <windows.h>
#include <stdio.h>

#include "Message.h"
#include "CheckSystem.h"
#include "Tools.h"
#include "LoadAPI.h"

BOOL CheckUserPrivilege(Advapi32_API advapi32, HANDLE hToken) {
	BOOL nbDetection = 0;
	const char* dangenrousPriv[] = {
		"SeImpersonatePrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",

		// TO CHECK -> https://github.com/hatRiot/token-priv/tree/master/poptoke/poptoke
		"SeCreateTokenPrivilege",
		//"SeLoadDriver",  -> A specified privilege does not exist. (Error 1313)
		"SeTakeOwnershipPrivilege",
		"SeTcbPrivilege",
		"SeDebugPrivilege",
		"SeSecurityPrivilege",
	};

	
	for (int i = 0; i < sizeof(dangenrousPriv) / sizeof(char*); i++) {
		if (IsUserPrivilegeEnable(advapi32, hToken, (char*)dangenrousPriv[i])) {
			if (nbDetection == 0) {
				printf("\n");
				printMsg(STATUS_TITLE, LEVEL_VERBOSE, "Check User Privilege\n");			
			}
			printMsg(STATUS_WARNING, LEVEL_DEFAULT, "User as %s privilage -> PrivEsc !!!\n", dangenrousPriv[i]);
			nbDetection++;
		}
	}
	return nbDetection;
}

BOOL IsTokenService(Kernel32_API kernel32, Advapi32_API advapi32, HANDLE hToken) {
	AccountInformation* accountInformation = NULL;

	if (GetAccountInformation(kernel32, advapi32,hToken, &accountInformation) && accountInformation != NULL) {
		const char* targetUsers[] = {
			"NETWORK SERVICE",
			"LOCAL SERVICE",
			"SERVICE",
			"SYSTEM",
		};
		int iUser = isStrInTable(accountInformation->UserName, (char**)targetUsers, sizeof(targetUsers) / sizeof(char*));
		if (iUser != NOT_FOUND) {
			printMsg(STATUS_OK, LEVEL_DEFAULT, "User account:\t%s\\%s\n", accountInformation->DomainName, accountInformation->UserName);
			printMsg(STATUS_OK, LEVEL_DEFAULT, "User SID:\t\t%s\n", accountInformation->SID);
			return TRUE;
		}
		free(accountInformation);
	}
	return FALSE;
}