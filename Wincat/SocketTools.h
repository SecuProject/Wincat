#pragma once

#ifndef SOCKET_TOOLS_HEADER_H
#define SOCKET_TOOLS_HEADER_H


typedef UINT_PTR        SOCKET;

DWORD DisplayError(LPWSTR pszAPI);
SOCKET ConnectRemoteServer(char* ipAddress, int port);
struct sockaddr_in InitSockAddr(char* ipAddress, int port);


#include <LoadAPI.h>

BOOL SendInitInfo(Kernel32_API kernel32, Advapi32_API advapi32, SOCKET mySocket, HANDLE hToken);
#endif