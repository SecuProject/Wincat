#pragma once

#ifndef TOOLS_HEADER_H
#define TOOLS_HEADER_H

//#define IP_ADDRESS_SIZE		40
#define IP_ADDRESS_SIZE		16

BOOL ReadRegistryValue(HKEY key, char* path, char* name, LPBYTE valueOutput, DWORD valueOutputSize);
BOOL checkKey(const char* subKeyTab);
BOOL SetRegistryValue(HKEY key, char* path, char* name, char* value);
BOOL DeleteRegistryKey(HKEY key, char* path, char* name);
BOOL RegDelnodeRecurse(HKEY hKeyRoot, char* lpSubKey);
BOOL SaveCPathInfo(char* currentPath);

BOOL SaveRHostInfo(WCHAR* UipAddress, char* port);




BOOL RunAs(char* executablePath, char* lpParameters);
BOOL Run(char* executablePath, char* lpParameters);

void DisableWindowsRedirection(PVOID* pOldVal);
void RevertWindowsRedirection(PVOID pOldVal);


BOOL isArgHostSet();
BOOL IsFileExist(char* filePath);
//void gen_random(char* string, const int len);
VOID GenRandDriverName(char* string, UINT len);

VOID ToLower(char* str1, size_t sizeStr1, char* str2);
BOOL CheckStrMatch(char* str1, const char* str2);

BOOL initWSAS();

#endif