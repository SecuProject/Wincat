#pragma once

#ifndef SOCKET_TOOLS_HEADER_H
#define SOCKET_TOOLS_HEADER_H

typedef UINT_PTR        SOCKET;

DWORD DisplayError(LPWSTR pszAPI);
BOOL SendInitInfo(SOCKET mySocket);


#endif