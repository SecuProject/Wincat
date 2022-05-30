#include <windows.h>
#include <stdio.h>

#include "Message.h"
#include "CheckSystem.h"
#include "Tools.h"


BOOL CheckUserPrivilege(HANDLE hToken) {

	const char* dangenrousPriv[] = {
		"SeImpersonatePrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",

		// TO CHECK -> https://github.com/hatRiot/token-priv/tree/master/poptoke/poptoke
		"SeCreateTokenPrivilege",
		"SeLoadDriver",
		"SeTakeOwnershipPrivilege",
		"SeTcbPrivilege",
		"SeDebugPrivilege",
		"SeSecurityPrivilege",

	};

	printMsg(STATUS_TITLE, LEVEL_VERBOSE, "Check User Privilege\n");
	for (int i = 0; i < sizeof(dangenrousPriv) / sizeof(char*); i++) {
		if (IsUserPrivilegeEnable(hToken, (char*)dangenrousPriv[i]))
			printMsg(STATUS_WARNING, LEVEL_DEFAULT, "User as %s privilage -> PrivEsc !!!\n", dangenrousPriv[i]);
	}
	return FALSE;
}

BOOL IsTokenService(HANDLE hToken) {
	AccountInformation* accountInformation = NULL;

	if (GetAccountInformation(hToken, &accountInformation) && accountInformation != NULL) {
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