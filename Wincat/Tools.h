#pragma once

#ifndef TOOLS_HEADER_H
#define TOOLS_HEADER_H

#define IP_ADDRESS_SIZE		16
#define NOT_FOUND			-1

#include "loadAPI/LoadAPI.h"

BOOL ReadRegistryValue(Advapi32_API Advapi32, HKEY key, char* path, char* name, LPBYTE valueOutput, DWORD valueOutputSize);
BOOL checkKey(Advapi32_API Advapi32, const char* subKeyTab);
BOOL CheckExistKey(Advapi32_API Advapi32, const char* subKeyTab);
BOOL SetRegistryValue(Advapi32_API Advapi32, HKEY key, char* path, char* name, char* value);
BOOL DeleteRegistryKey(Advapi32_API Advapi32, HKEY key, char* path, char* name);
BOOL RegDelnodeRecurse(Advapi32_API Advapi32, HKEY hKeyRoot, char* lpSubKey);
BOOL SaveCPathInfo(Advapi32_API Advapi32, char* currentPath);

BOOL SaveRHostInfo(Advapi32_API Advapi32, WCHAR* UipAddress, char* port);




BOOL RunAs(Shell32_API shell32, char* executablePath, char* lpParameters);
BOOL Run(Shell32_API shell32, char* executablePath, char* lpParameters);

void DisableWindowsRedirection(PVOID* pOldVal);
void RevertWindowsRedirection(PVOID pOldVal);


BOOL isArgHostSet(Advapi32_API Advapi32);
BOOL IsFileExist(char* filePath);
//void gen_random(char* string, const int len);
VOID GenRandDriverName(char* string, UINT len);

VOID ToLower(char* str1, size_t sizeStr1, char* str2);
BOOL CheckStrMatch(char* str1, const char* str2);
int isStrInTable(char* string, char** strTable, int tableSize);

BOOL initWSAS();

#endif