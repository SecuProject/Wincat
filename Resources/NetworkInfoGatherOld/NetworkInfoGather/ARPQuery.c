
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "Network.h"
#include "Tools.h"


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma warning(disable:4996)


#define IP_ADDRESS_SIZE			15
#define MAC_ADDRESS_SIZE_BYTE	6

typedef struct {
	char ipAddess[IP_ADDRESS_SIZE + 1];
	char macAddress[MAC_ADDRESS_SIZE_BYTE * 2 + 1];
}Host_ID;


BOOL arpScan(char* ipAddress, char* macAddress, Host_ID* hostId) {
	IPAddr DestIp = inet_addr(ipAddress);
	IPAddr SrcIp = 0;

	ULONG MacAddr[2];
	ULONG PhysAddrLen = MAC_ADDRESS_SIZE_BYTE;  /* default to length of six bytes */
	DWORD dwRetVal;

	memset(&MacAddr, 0xff, sizeof(MacAddr));
	dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);

	if (dwRetVal == NO_ERROR) {
		BYTE *bPhysAddr;

		strcpy_s(hostId->ipAddess, IP_ADDRESS_SIZE + 1, ipAddress);
		bPhysAddr = (BYTE *)& MacAddr;
		if (PhysAddrLen) {
			sprintf_s(hostId->macAddress, MAC_ADDRESS_SIZE_BYTE * 2 + 1, "%.2X%.2X%.2X%.2X%.2X%.2X",
				bPhysAddr[0], bPhysAddr[1], bPhysAddr[2], bPhysAddr[3], bPhysAddr[4], bPhysAddr[5]);
			return TRUE;
		}
	}
	return FALSE;
}


BOOL ARPdiscovery(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile) {
	NetworkPcInfo* networkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);
	if (networkPcInfo == NULL)
		return FALSE;

	Host_ID *hostId = (Host_ID*)calloc(sizeof(Host_ID), 1);
	if (hostId == NULL)
		return FALSE;

	printOut(pFile,"[i] ARP discovery:\n");
	for (int i = 1; i < maskSizeInt; i++) {
		char* ip = (char*)calloc(IP_SIZE_CHAR, 1);
		if (ip != NULL) {
			INT32 ipAddress = ipAddressBc + i;
			sprintf_s(ip, IP_SIZE_CHAR, "%i.%i.%i.%i",
				(ipAddress >> 24)				& OCTE_MAX, //  << 24; // (OCTE_SIZE * 4)
				(ipAddress >> OCTE_SIZE * 2)	& OCTE_MAX,
				(ipAddress >> OCTE_SIZE)		& OCTE_MAX,
				ipAddress						& OCTE_MAX);
			if (arpScan(ip, NULL, hostId)) {
				printOut(pFile,"\t[%i] Detected - [%s:%s]\n", (*nbDetected) + 1, hostId->ipAddess, hostId->macAddress);

				networkPcInfo[*nbDetected].ipAddress = (char*)malloc(IP_SIZE_CHAR);
				if (networkPcInfo[*nbDetected].ipAddress == NULL)
					return FALSE;
				strcpy_s(networkPcInfo[*nbDetected].ipAddress, IP_SIZE_CHAR, ip);


				networkPcInfo[*nbDetected].macAddress = (char*)malloc(IP_SIZE_CHAR);
				if (networkPcInfo[*nbDetected].macAddress == NULL)
					return FALSE;
				strcpy_s(networkPcInfo[*nbDetected].macAddress, IP_SIZE_CHAR, ip);

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
	free(hostId);

	*ptrNetworkPcInfo = networkPcInfo;
	return TRUE;
}