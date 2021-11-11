#include <Windows.h>
#include <stdio.h>

#include "AdapterInformation.h"
#include "NetDiscovery.h"
#include "Network.h"
#include "PortScan.h"
#include "PortFingerPrint.h"
#include "MgArguments.h"
#include "Tools.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_NB_ADAPTER	50

void freeStrcutFP(NetworkPcInfo* networkPcInfo, int nbDetected) {
	for (int i = nbDetected - 1; i >= 0; i--) {
		if (networkPcInfo[i].ipAddress != NULL)
			free(networkPcInfo[i].ipAddress);
		if (networkPcInfo[i].vendorName != NULL)
			free(networkPcInfo[i].vendorName);
	}
	free(networkPcInfo);
}

BOOL AddIPRange(NetworkPcInfo** ppNetworkPcInfo,int* nbDetected, char* ipRange) {
	int a, b, c, d;
	char* ptr;
	NetworkPcInfo* pNetworkPcInfo = *ppNetworkPcInfo;

	ptr = strchr(ipRange, '-');
	if (ptr != NULL) {
		unsigned int range;
		if (sscanf_s(ipRange, "%i.%i.%i.%i-%i", &a, &b, &c, &d,&range) != 5)
			return FALSE;
		*nbDetected = range - d +1;

		pNetworkPcInfo = (NetworkPcInfo*)calloc(*nbDetected +1, sizeof(NetworkPcInfo));
		if (pNetworkPcInfo == NULL)
			return FALSE;

		if (*nbDetected > 0 && *nbDetected < 256) {
			for (int i = 0; i < *nbDetected; i++) {
				int subNet = 0;
				pNetworkPcInfo[i].ipAddress = (char*)calloc(IP_SIZE_CHAR + 1, 1);
				if (pNetworkPcInfo[i].ipAddress == NULL)
					return FALSE;

				if (d + i == 255) {
					d = 0;
					subNet = 1;
				}
				sprintf_s(pNetworkPcInfo[i].ipAddress, IP_SIZE_CHAR + 1,"%d.%d.%d.%d", a, b, c + subNet, d +i);
			}
		} else
			return FALSE;
	} else {
		if (sscanf_s(ipRange, "%i.%i.%i.%i", &a, &b, &c, &d) != 4)
			return FALSE;

		*nbDetected = 1;
		pNetworkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);
		if (pNetworkPcInfo == NULL)
			return FALSE;
		pNetworkPcInfo[0].ipAddress = (char*)calloc(IP_SIZE_CHAR + 1, 1);
		if (pNetworkPcInfo[0].ipAddress == NULL)
			return FALSE;
		if (sscanf_s(ipRange, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
			return FALSE;
		strcpy_s(pNetworkPcInfo[0].ipAddress, IP_SIZE_CHAR + 1, ipRange);
	}
	*ppNetworkPcInfo = pNetworkPcInfo;
	return TRUE;
}


int main(int argc, char* argv[]) {
	Arguments listAgrument;

	if (!GetArguments(argc, argv, &listAgrument))
		return FALSE;

	ADAPTER_INFO *adapterInfo=(ADAPTER_INFO *)calloc(sizeof(ADAPTER_INFO), MAX_NB_ADAPTER);
	if(adapterInfo == NULL)
		return FALSE;
	int nbAdapter = getAdapterkInfo(adapterInfo, listAgrument.ouputFile);
	if (nbAdapter == 0) {
		printOut(listAgrument.ouputFile,"[x] No network interface detected !\n");
		free(adapterInfo);
		return FALSE;
	}
	if (!initWSA(listAgrument.ouputFile))
		return FALSE;

	if (listAgrument.isListInterface) {
		for (int i = 0; i < nbAdapter; i++) {
			INT32 ipRangeInt32 = 0;
			int maskSizeInt = 0;
			int nbDetected = 0;
			NetworkPcInfo* networkPcInfo = NULL;

			ipRangeInt32 = ipCalucation(adapterInfo[i].localIP, adapterInfo[i].networkMask, &maskSizeInt) + 1;
			printOut(listAgrument.ouputFile,"[ Adapter %i ] GW %s - MASK %s - Local IP %s\n", i + 1, adapterInfo[i].GateWayIp, adapterInfo[i].networkMask, adapterInfo[i].localIP);
		}
	} else{
		if (listAgrument.interfaceNb < nbAdapter  +1) {
			INT32 ipRangeInt32 = 0;
			int maskSizeInt = 0;
			int nbDetected = 0;
			NetworkPcInfo* networkPcInfo = NULL;
			ADAPTER_INFO adapterInfoSelected = adapterInfo[listAgrument.interfaceNb - 1];

			ipRangeInt32 = ipCalucation(adapterInfoSelected.localIP, adapterInfoSelected.networkMask, &maskSizeInt) + 1;
			printOut(listAgrument.ouputFile, "[ Adapter %i ] GW %s - MASK %s - Local IP %s\n",  listAgrument.interfaceNb, adapterInfoSelected.GateWayIp, adapterInfoSelected.networkMask, adapterInfoSelected.localIP);



			// FILE* pFile
			/*nbDetected = 1;
			networkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);
			networkPcInfo[0].ipAddress = "192.168.100.10";
			networkPcInfo[0].osName = OsWindows;

			scanPort(networkPcInfo, nbDetected, listAgrument.ouputFile);
			PortFingerPrint(networkPcInfo, nbDetected, listAgrument.bruteforce, listAgrument.ouputFile);
			return FALSE;*/

			/*
			nbDetected = 1;
			networkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);
			networkPcInfo[0].ipAddress = "192.168.100.40";
			networkPcInfo[0].osName = OsLinux;

			scanPort(networkPcInfo, nbDetected);
			PortFingerPrint(networkPcInfo, nbDetected, listAgrument.bruteforce);
			return FALSE;
			*/

			if (listAgrument.ipAddress != NULL) {
				if (!AddIPRange(&networkPcInfo, &nbDetected, listAgrument.ipAddress))
					return TRUE;

				scanPort(networkPcInfo, nbDetected, listAgrument.ouputFile);
				if (listAgrument.advancedScan) {
					PortFingerPrint(networkPcInfo, nbDetected, listAgrument.bruteforce, listAgrument.ouputFile); // BOOL
				}

			}else if (NetDiscovery(listAgrument, ipRangeInt32, maskSizeInt, adapterInfoSelected.localIP, &networkPcInfo, &nbDetected, listAgrument.ouputFile)) {
				if (listAgrument.portScan) {
					scanPort(networkPcInfo, nbDetected, listAgrument.ouputFile);
					if (listAgrument.advancedScan) {
						PortFingerPrint(networkPcInfo, nbDetected, listAgrument.bruteforce, listAgrument.ouputFile); // BOOL
					}
				}
				//startAttack(networkPcInfo, nbDetected, adapterInfo[i].localIP);
			}
		}
	}




	WSACleanup();
	free(adapterInfo);
	if(listAgrument.ipAddress != NULL)
		free(listAgrument.ipAddress);
	return FALSE;

	/////////////////////////////////////////////:::
	/////////////////////////////////////////////:::
	/////////////////////////////////////////////:::
	/////////////////////////////////////////////:::
	/////////////////////////////////////////////:::

	for (int i = 0; i < nbAdapter; i++) {
		INT32 ipRangeInt32 = 0;
		int maskSizeInt = 0;
		int nbDetected = 0;
		NetworkPcInfo* networkPcInfo = NULL;

		ipRangeInt32 = ipCalucation(adapterInfo[i].localIP, adapterInfo[i].networkMask, &maskSizeInt) + 1;
		printOut(listAgrument.ouputFile,"[ Adapter %i ] GW %s - MASK %s - Local IP %s\n", i + 1, adapterInfo[i].GateWayIp, adapterInfo[i].networkMask, adapterInfo[i].localIP);

		// Passif_Scan ICMP_Scan ARP_Scan
		/*if (NetDiscovery(Passif_Scan, ipRangeInt32 , maskSizeInt,&networkPcInfo,&nbDetected)) {
			//scanPort(networkPcInfo, nbDetected);
			//PortFingerPrint(networkPcInfo, nbDetected); // BOOL
			//startAttack(networkPcInfo, nbDetected, adapterInfo[i].localIP);
		}*/

		/*
		nbDetected = 1;
		networkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo),1);
		networkPcInfo[0].ipAddress = (char*)calloc(25,1);
		networkPcInfo[0].ipAddress = "192.168.100.40";

		scanPort(networkPcInfo, nbDetected);
		PortFingerPrint(networkPcInfo, nbDetected);*/

		freeStrcutFP(networkPcInfo, nbDetected);
	}
	system("pause");
	WSACleanup();
	free(adapterInfo);
	return 0;
}
