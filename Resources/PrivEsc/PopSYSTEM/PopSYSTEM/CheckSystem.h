#pragma once

#ifndef CHECK_SYSTEM_HEADER_H
#define CHECK_SYSTEM_HEADER_H

BOOL IsWindowsVistaOrGreater();
BOOL IsRunAsAdmin();
BOOL IsUserInAdminGroup();

BOOL EnableWindowsPrivilege(LPCWSTR Privilege);
BOOL CheckWindowsPrivilege(LPCWSTR Privilege);
HANDLE GetAccessToken(DWORD pid);
int GetTargetProcessPID(WCHAR* processName);

#endif