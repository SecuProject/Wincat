#include <Windows.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include "Network.h"
#include "Tools.h"


#pragma warning(disable:4996)

// set to (rand() % 3) + 3
#define NB_TIME_PING	(rand() % 2) + 3



#define SEND_DATA_SIZE	32

// 0.5s => 5 * 100
#define TIME_OUT_PING   1000
#define SLEEP_TIME		100


/*
	Linux base					64
	Windows						128
	iOS 12.4 (Cisco Routers)	255
*/


int pingFunctionLoop(HANDLE hIcmpFile, IPAddr ipaddr, char* SendData, LPVOID ReplyBuffer, DWORD ReplySize,int* pComputerTTL) {
	int nbReceived = 0;
	int computerTTL = 0;
	int nbTimePing = NB_TIME_PING;
	for (int i = 0; i < nbTimePing; i++) {
		DWORD dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, SEND_DATA_SIZE, NULL, ReplyBuffer, ReplySize, TIME_OUT_PING);
		if (dwRetVal != 0) {
			PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
			struct in_addr ReplyAddr;
			ReplyAddr.S_un.S_addr = pEchoReply->Address;
			computerTTL += pEchoReply->Options.Ttl;
			if (pEchoReply->Status == 0) {
				nbReceived++;
			}
		}
		else
			return FALSE;
		Sleep(TIME_OUT_PING);
	}
	*pComputerTTL = (int)(computerTTL / nbTimePing);
	return nbReceived;
}


BOOL startPinging(char* ipAddress, int* computerTTL, FILE* pFile) {
	BOOL detected = FALSE;
	HANDLE hIcmpFile = IcmpCreateFile();

	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		printOut(pFile,"\tUnable to open handle.\n");
		printOut(pFile,"IcmpCreatefile returned error: %ld\n", GetLastError());
		return FALSE;
	}
	else {
		LPVOID ReplyBuffer = NULL;
		DWORD ReplySize = sizeof(ICMP_ECHO_REPLY) + SEND_DATA_SIZE;
		IPAddr ipaddr = inet_addr(ipAddress);

		if (ipaddr == INADDR_NONE) {
			printOut(pFile,"[X] Error ip !!!\n");
			return FALSE;
		}


		ReplyBuffer = (VOID*)calloc(ReplySize, 1);
		if (ReplyBuffer == NULL) {
			printOut(pFile,"\tUnable to allocate memory\n");
			return FALSE;
		}
		else {
			//char SendData[SEND_DATA_SIZE] = "Data Buffer";
			char SendData[SEND_DATA_SIZE + 1] = {
			0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
			0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69 };
			 detected = pingFunctionLoop(hIcmpFile, ipaddr, SendData, ReplyBuffer, ReplySize, computerTTL) > 1;
			free(ReplyBuffer);
		}
		IcmpCloseHandle(hIcmpFile);
	}
	return detected;
}

EnumOS DetectOSBaseTTL(int computerTTL, FILE* pFile) {
	if (computerTTL < 65) {
		printOut(pFile,"\t\t[i] Linux base\n");
		return OsLinux;
	}
	else if (computerTTL > 64 || computerTTL < 129) {
		printOut(pFile,"\t\t[i] Windows\n");
		return OsWindows;
	}
	else if (computerTTL < 256) {
		printOut(pFile,"\t\t[i] Cisco\n");
		return OsCisco;
	}
	return OsUnknown;
}

BOOL ICMPdiscovery(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);

	if (networkPcInfo == NULL)
		return FALSE;

	printOut(pFile,"[i] ICMP discovery:\n");
	for (int i = 0; i < maskSizeInt; i++) {
		int computerTTL = 0;
		char* ip = (char*)calloc(IP_SIZE_CHAR, 1);
		if (ip != NULL) {
			INT32 ipAddress = ipAddressBc + i;
			sprintf_s(ip, IP_SIZE_CHAR, "%i.%i.%i.%i",
				(ipAddress >> 24)				& OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
				(ipAddress >> OCTE_SIZE * 2)	& OCTE_MAX,
				(ipAddress >> OCTE_SIZE)		& OCTE_MAX,
				ipAddress						& OCTE_MAX);


		/*	sprintf_s(ip, IP_SIZE_CHAR, "192.168.1.%i",
				ipAddress						& OCTE_MAX);*/


			//printOut(pFile,"\t[i] Scanning - [%s]\n", ip);
			if (startPinging(ip,&computerTTL,pFile)) {
				printOut(pFile,"\t[%i] Detected - [%s]\n", (*nbDetected) + 1, ip);

				networkPcInfo[*nbDetected].ipAddress = (char*)malloc(IP_SIZE_CHAR);
				if (networkPcInfo[*nbDetected].ipAddress == NULL)
					return FALSE;
				strcpy_s(networkPcInfo[*nbDetected].ipAddress, IP_SIZE_CHAR, ip);
				networkPcInfo[*nbDetected].osName = DetectOSBaseTTL(computerTTL,pFile);
				networkPcInfo = (NetworkPcInfo*)realloc(networkPcInfo, ((*nbDetected) + 2) * sizeof(NetworkPcInfo));
				if (networkPcInfo == NULL)
					return FALSE;
				(*nbDetected)++;
			}
			free(ip);
		}
		else
			return FALSE;
	}

	*ptrNetworkPcInfo = networkPcInfo;
	return TRUE;
}