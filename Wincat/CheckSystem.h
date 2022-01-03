#pragma once

#ifndef CHECK_SYSTEM_HEADER_H
#define CHECK_SYSTEM_HEADER_H



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
HANDLE GetAccessToken(DWORD pid);
int GetTargetProcessPID(WCHAR* processName);



BOOL IsUACEnabled();
UAC_POLICY CheckUACSettings();

#endif