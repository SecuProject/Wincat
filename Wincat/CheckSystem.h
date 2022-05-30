#pragma once

#ifndef CHECK_SYSTEM_HEADER_H
#define CHECK_SYSTEM_HEADER_H

#define MAX_NAME	256

typedef struct {
	char UserName[MAX_NAME];
	char DomainName[MAX_NAME];
	char SID[MAX_NAME];
}AccountInformation, * PAccountInformation;

typedef enum {
	UAC_POLICY_ERROR,
	UAC_POLICY_DEFAULT,
	UAC_POLICY_ALWAYS_NOTIFY,
	UAC_POLICY_DISABLE,
}UAC_POLICY;


BOOL IsWindowsVistaOrGreater();
BOOL IsRunAsAdmin();
BOOL IsRunAsSystem();
BOOL IsUserInAdminGroup();

BOOL EnableWindowsPrivilege(LPCWSTR Privilege);
BOOL CheckWindowsPrivilege(LPCWSTR Privilege);
BOOL IsUserPrivilegeEnable(HANDLE hToken, char* priv);

HANDLE GetAccessToken(DWORD pid);
int GetTargetProcessPID(WCHAR* processName);
BOOL GetAccountInformation(HANDLE hToken, PAccountInformation* ppAccountInformation);


BOOL IsUACEnabled();
UAC_POLICY CheckUACSettings();

#endif