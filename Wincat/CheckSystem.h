#pragma once

#ifndef CHECK_SYSTEM_HEADER_H
#define CHECK_SYSTEM_HEADER_H

#define MAX_NAME	256

#include "LoadAPI.h"

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
BOOL IsRunAsAdmin(Advapi32_API advapi32Api);
BOOL IsRunAsSystem(Kernel32_API kernel32);
BOOL IsUserInAdminGroup(Kernel32_API kernel32, Advapi32_API advapi32);

BOOL EnableWindowsPrivilege(Advapi32_API advapi32,LPCWSTR Privilege);
BOOL CheckWindowsPrivilege(Kernel32_API kernel32, Advapi32_API advapi32, LPCWSTR Privilege);
BOOL IsUserPrivilegeEnable(Advapi32_API advapi32, HANDLE hToken, char* priv);

HANDLE GetAccessToken(Kernel32_API kernel32, Advapi32_API advapi32, DWORD pid);
int GetTargetProcessPID(Kernel32_API kernel32, WCHAR* processName);
BOOL GetAccountInformation(Kernel32_API kernel32, Advapi32_API advapi32, HANDLE hToken, PAccountInformation* ppAccountInformation);


BOOL IsUACEnabled(Advapi32_API advapi32);
UAC_POLICY CheckUACSettings(Advapi32_API advapi32);

#endif