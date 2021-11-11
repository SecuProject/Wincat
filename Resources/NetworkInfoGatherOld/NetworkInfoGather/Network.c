#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

#include "portList.h"
#include "Tools.h"

/*
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5357/tcp open  wsdapi
*/

const int port[] = {
	PORT_FTP,
	PORT_SSH,
	PORT_TELNET,
	PORT_DNS,
	PORT_HTTP,
	PORT_KERBEROS,
	PORT_HTTP_TOMCAT,
	PORT_HTTP_PROXY,
	PORT_HTTP_OTHER,
	PORT_NETBIOS_SSN,
	PORT_HTTPS,
	PORT_SMB,
	PORT_MSSQL,
	PORT_ORACLEDB,
	PORT_MYSQL,
	PORT_POSTGRESQL,
	PORT_WINRM
};

BOOL initWSA(FILE* pFile) {
	WSADATA wsa;

	//printOut(pFile,"[i] Initialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		printOut(pFile,"[x] Failed. Error Code : %d", WSAGetLastError());
		return FALSE;
	}
	//printOut(pFile,"Initialised.\n");
	return TRUE;
}