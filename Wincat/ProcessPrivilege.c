#include <windows.h>
#include <stdio.h>
#include <sddl.h>

#include "Message.h"
#include "CheckSystem.h"


BOOL CheckUserPrivilege(HANDLE hToken) {

	const char* dangenrousPriv[] = {
		"SeImpersonatePrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege"
	};

	printMsg(STATUS_TITLE, LEVEL_VERBOSE, "Check User Privilege\n");
	for (int i = 0; i < sizeof(dangenrousPriv) / sizeof(char*); i++) {
		if (IsUserPrivilegeEnable(hToken, (char*)dangenrousPriv[i]))
			printMsg(STATUS_WARNING, LEVEL_DEFAULT, "User as %s privilage -> PrivEsc !!!\n", dangenrousPriv[i]);
	}
	return FALSE;
}

BOOL IsTokenService(HANDLE hToken) {
	DWORD tokenSize = 0;
	TOKEN_USER* User;

	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenSize)) {
		DWORD dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "GetTokenInformation Error");
			return FALSE;
		}
	}
	User = (TOKEN_USER*)malloc(tokenSize);
	if (User != NULL) {
		if (GetTokenInformation(hToken, TokenUser, User, tokenSize, &tokenSize)) {
			SID_NAME_USE SidType;
			char UserName[64], DomainName[64];
			DWORD UserSize = 64 - 1, DomainSize = 64 - 1;

			if (LookupAccountSidA(NULL, User->User.Sid, UserName, &UserSize, DomainName, &DomainSize, &SidType)) {
				const char* targetUsers[] = {
					"NETWORK SERVICE",
					"LOCAL SERVICE",
					"SYSTEM"
				};

				for (int i = 0; i < sizeof(targetUsers) / sizeof(char*); i++) {
					if (strcmp(UserName, (char*)targetUsers[i]) == 0) {
						LPSTR lpSID = NULL;

						printMsg(STATUS_TITLE, LEVEL_DEFAULT, "Check Token Service\n");
						if (ConvertSidToStringSidA(User->User.Sid, &lpSID)) {
							printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Account SID: %s\n", lpSID);
							LocalFree(lpSID);
						}
						else
							printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Account SID: N/A\n");
						printMsg(STATUS_WARNING2, LEVEL_DEFAULT, "User account: %s\\%s\n", DomainName, UserName);
					}
				}
			}
		}
		free(User);
	}
	return TRUE;
}