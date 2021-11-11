#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#include "Network.h"
#include "portList.h"
#include "EnumHTTP.h"
#include "Tools.h"

#pragma warning(disable:4996)  // for inet_addr

int set_options(SOCKET fd) {
	struct timeval timeout;

	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != SOCKET_ERROR; // if setsockopt == fail => return 0;
}

BOOL scanPortOpenTCP(char* dest_ip, int port,FILE* pFile) {
	SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (tcp_sock == INVALID_SOCKET) {
		printOut(pFile,"[X] socket open failed %ld\n", GetLastError());
		closesocket(tcp_sock);
		return FALSE;
	} else {
		SOCKADDR_IN ssin;

		memset(&ssin, 0, sizeof(SOCKADDR_IN));
		ssin.sin_family = AF_INET;
		ssin.sin_port = htons(port);
		ssin.sin_addr.s_addr = inet_addr(dest_ip);

		if (!set_options(tcp_sock)) {
			printOut(pFile,"[X] Error setting socket options\n");
			closesocket(tcp_sock);
			return FALSE;
		}
		if (connect(tcp_sock, (struct sockaddr*)&ssin, sizeof(SOCKADDR_IN)) != SOCKET_ERROR) {
			closesocket(tcp_sock);
			return TRUE;
		}
	}
	closesocket(tcp_sock);
	return FALSE;
}

void scanPort(NetworkPcInfo* networkPcInfo, int nbDetected, FILE* pFile) {
	for (int iPC = 0; iPC < nbDetected; iPC++) {
		printOut(pFile,"[%s] PORT SCAN\n", networkPcInfo[iPC].ipAddress);
		networkPcInfo[iPC].nbOpenPort = 0;
		for (int iPort = 0; iPort < NB_TAB_PORT; iPort++) {
			if(scanPortOpenTCP(networkPcInfo[iPC].ipAddress, port[iPort],pFile)) {
				printOut(pFile,"\t[%s] OPEN PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);
				networkPcInfo[iPC].port[networkPcInfo[iPC].nbOpenPort].portNumber = port[iPort];
				networkPcInfo[iPC].nbOpenPort++;
			}/*else
				printOut(pFile,"\t[%s] CLOSE PORT %i\n", networkPcInfo[iPC].ipAddress, port[iPort]);*/
		}
	}
	return;
}