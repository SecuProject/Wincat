#include <WinSock2.h>
#include <stdio.h>
#include <	ws2tcpip.h>

#include "CheckSystem.h"
#include "SocketTools.h"
#include "Message.h"
#include "Tools.h"

#define UNLEN					256
#define BUF_SIZE				1000


BOOL GetIpAddress(SOCKET mysocket,char* ipAddress) {
	struct sockaddr_in name;
	int namelen = sizeof(struct sockaddr_in);

	if (getsockname(mysocket, (struct sockaddr*)&name, &namelen) != SOCKET_ERROR) {
		const char* p = inet_ntop(AF_INET, &name.sin_addr, ipAddress, IP_ADDRESS_SIZE);
		return p != NULL;

	}
	return FALSE;
}

// hToken
BOOL SendInitInfo(SOCKET mysocket, HANDLE hToken) {
	AccountInformation* accountInformation = NULL;

	if (GetAccountInformation(hToken, &accountInformation) && accountInformation != NULL) {
		char* sendBuffer = (char*)malloc(BUF_SIZE);
		if (sendBuffer != NULL) {
			char* ipAddress = (char*)malloc(IP_ADDRESS_SIZE);
			if (ipAddress != NULL) {
				int sizeBuffer;

				if (GetIpAddress(mysocket, ipAddress))
					sizeBuffer = sprintf_s(sendBuffer, BUF_SIZE, "[+] Connected as %s\\%s from %s\n\n", accountInformation->DomainName, accountInformation->UserName, ipAddress);
				else
					sizeBuffer = sprintf_s(sendBuffer, BUF_SIZE, "[+] Connected as %s\\%s\n\n", accountInformation->DomainName, accountInformation->UserName);
				send(mysocket, sendBuffer, sizeBuffer, 0);
				free(ipAddress);
			}
			free(sendBuffer);
			free(accountInformation);
			return TRUE;
		}
		free(accountInformation);
	}
	return FALSE;
}
/*
BOOL SendInitInfo(SOCKET mysocket, HANDLE hToken) {
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