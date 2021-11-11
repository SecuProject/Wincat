#include <WinSock2.h>
#include <stdio.h>

#include "SocketTools.h"
#include "Message.h"

#define UNLEN					256
#define BUF_SIZE				1000

BOOL SendInitInfo(SOCKET mysocket) {
	char* userName;
	char* hostname;
	int sizeBufUsername = UNLEN + 1;

	userName = (char*)calloc(UNLEN + 1, sizeof(char));
	if (userName == NULL) {
		return FALSE;
	}
	if (!GetUserNameA(userName, &sizeBufUsername)) {
		free(userName);
		return FALSE;
	}
	hostname = (char*)calloc(UNLEN + 1, sizeof(char));
	if (hostname == NULL) {
		free(userName);
		return FALSE;
	}

	if (gethostname(hostname, UNLEN + 1) != SOCKET_ERROR) {
		struct sockaddr_in name;
		int len = sizeof(name);
		if (getpeername(mysocket, (struct sockaddr*)&name, &len) != SOCKET_ERROR) {
			char* sendBuffer = (char*)calloc(BUF_SIZE, sizeof(char));
			int sizeHostName;
			if (sendBuffer == NULL) {
				free(hostname);
				free(userName);
				return FALSE;
			}
			sizeHostName = sprintf_s(sendBuffer, BUF_SIZE, "[+] Connected as %s from %s\n\n", userName, hostname);
			send(mysocket, sendBuffer, sizeHostName, 0);
			free(sendBuffer);
		}
	}
	free(hostname);
	free(userName);
	return TRUE;
}


/*VOID SendInitInfo(SOCKET mysocket) {
	char* userName;
	char* hostname;
	int sizeBufUsername = UNLEN + 1;

	userName = (char*)calloc(UNLEN + 1, sizeof(char));
	if (userName == NULL) {
		return;
	}
	if (!GetUserNameA(userName, &sizeBufUsername)) {
		free(userName);
		return;
	}
	hostname = (char*)calloc(UNLEN + 1, sizeof(char));
	if (hostname == NULL) {
		free(userName);
		return;
	}

	if (gethostname(hostname, UNLEN + 1) != SOCKET_ERROR) {
		struct sockaddr_in name;
		int len = sizeof(name);
		if (getpeername(mysocket, (struct sockaddr*)&name, &len) != SOCKET_ERROR) {
			char* sendBuffer = (char*)calloc(BUF_SIZE, sizeof(char));
			int sizeHostName;
			if (sendBuffer == NULL) {
				free(userName);
				return;
			}
			sizeHostName = sprintf_s(sendBuffer, BUF_SIZE, "[i] Connected as %s from %s (%s)\n\n", userName, hostname, inet_ntoa(name.sin_addr));
			send(mysocket, sendBuffer, sizeHostName, 0);
			free(sendBuffer);
		}
	}
	free(hostname);
	free(userName);
	return;
}*/