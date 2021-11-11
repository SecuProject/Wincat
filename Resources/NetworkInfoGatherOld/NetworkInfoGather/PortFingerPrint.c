#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#include "Network.h"
#include "EnumHTTP.h"
#include "EnumSMB.h"
#include "Tools.h"

#pragma warning(disable:4996)

#define NO_OFFSET			0
#define MYSQL_OFFSET		5

#define BANNER_BUFFER_SIZE	50

BOOL getBanner(char* protocalName, char* ipAddress, unsigned int port, char* buffer, int bufferSize, int offset, FILE* pFile) {
	SOCKET SocketFD;

	if ((SocketFD = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return FALSE;
	SOCKADDR_IN ssin;
	memset(&ssin, 0, sizeof(ssin));
	ssin.sin_family = AF_INET;
	ssin.sin_addr.s_addr = inet_addr(ipAddress);
	ssin.sin_port = htons(port);
	if (connect(SocketFD, (LPSOCKADDR)&ssin, sizeof(ssin)) != SOCKET_ERROR) {
		int sizeRecv = recv(SocketFD, buffer, bufferSize, 0);
		if (sizeRecv > 0) {
			printOut(pFile,"\t[%s] Banner %s", protocalName, buffer + offset);
			closesocket(SocketFD);
			return TRUE;
		}
	}
	closesocket(SocketFD);
	return FALSE;
}

BOOL PortFingerPrint(NetworkPcInfo* networkPcInfo, int nbDetected, BOOL isBruteforce, FILE* pFile) {
	for (int i = 0; i < nbDetected; i++) {
		char* ipAddress = networkPcInfo[i].ipAddress;
		int nbFPInfo = networkPcInfo[i].nbOpenPort;

		printOut(pFile,"[FingerPrint] %s\n", ipAddress);
		for (int j = 0; j < nbFPInfo; j++) {
			int portNb = networkPcInfo[i].port[j].portNumber;
			switch (portNb) {
			case PORT_SSH:
				getBanner("SSH",ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, NO_OFFSET,pFile);
				break;
			case PORT_FTP:
				getBanner("TELNET", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, NO_OFFSET,pFile);
				break;
			case PORT_MYSQL:
				getBanner("MYSQL", ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE, MYSQL_OFFSET,pFile);
				break;
			case PORT_HTTP:
			case PORT_HTTP_TOMCAT:
			case PORT_HTTP_PROXY:
			case PORT_HTTP_OTHER:
				EnumHTTP(ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE,pFile);
				break;
			case PORT_HTTPS:
				EnumHTTPS(ipAddress, portNb, networkPcInfo[i].port[j].banner, BANNER_BUFFER_SIZE,pFile);
				break;
			case PORT_SMB:
				SmbEnum(ipAddress, isBruteforce,pFile);
				break;
			default:
				break;
			}
		}
	}
	return FALSE;
}