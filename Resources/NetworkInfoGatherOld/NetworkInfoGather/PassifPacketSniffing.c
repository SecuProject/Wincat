#include <stdio.h>
#include <winsock2.h>
#include <time.h>


#include "tcpIpModuel.h"
#include "NetDiscovery.h"
#include "Tools.h"
#pragma warning(disable:4996)
#pragma comment(lib , "ws2_32.lib")


#define MAC_ADDRESS_SIZE	20
#define IP_ADDRESS_SIZE		16

#define IS_PRIVATE_IP(IP_ADDRESS)		(strncmp(IP_ADDRESS, "192.168.", 8) == 0 \
										||strncmp(IP_ADDRESS, "172.16.", 7) == 0 \
										|| strncmp(IP_ADDRESS, "10.", 3) == 0)

typedef struct {
	char ipAddress[IP_ADDRESS_SIZE];
	int ttlInfo[100];
	int nbTtlTable;
}PC_INFO;

EnumOS FingerPrinting(unsigned int ttl, FILE* pFile) {
	if (ttl <= 64) {
		printOut(pFile,"\tLinux %i\n", ttl);
		return OsLinux;
	}else if (ttl <= 128) {
		printOut(pFile,"\tWindows %i\n", ttl);
		return OsWindows;
	}else
		printOut(pFile,"\tCisco %i\n", ttl);
	return OsCisco;
}

BOOL ProcessPacket(char* Buffer, int Size, NetworkPcInfo** ppNetworkPcInfo, int* nbPcInfo, FILE* pFile) {
	char ipAddressSrc[IP_ADDRESS_SIZE];
	char ipAddressDst[IP_ADDRESS_SIZE];
	struct sockaddr_in source;
	struct sockaddr_in  dest;
	int iphdrlen;
	NetworkPcInfo* pNetworkPcInfo = *ppNetworkPcInfo;

	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	TCP_HDR* tcpHdr = (TCP_HDR*)(Buffer + sizeof(IPV4_HDR));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	strcpy_s(ipAddressSrc, IP_ADDRESS_SIZE, inet_ntoa(source.sin_addr));
	strcpy_s(ipAddressDst, IP_ADDRESS_SIZE, inet_ntoa(dest.sin_addr));

	// remove 192.168.x.255
	if (IS_PRIVATE_IP(ipAddressSrc)) {
		int iSrc;
		for (iSrc = 0; iSrc < *nbPcInfo && strcmp(pNetworkPcInfo[iSrc].ipAddress, ipAddressSrc) != 0; iSrc++);
		if (iSrc == *nbPcInfo) {
			pNetworkPcInfo[*nbPcInfo].ipAddress = (char*)calloc(IP_ADDRESS_SIZE + 1, 1);
			if (pNetworkPcInfo[*nbPcInfo].ipAddress == NULL)
				return FALSE;
			strcpy_s(pNetworkPcInfo[*nbPcInfo].ipAddress, IP_ADDRESS_SIZE, ipAddressSrc);
			
			pNetworkPcInfo[*nbPcInfo].macAddress = NULL;
			printOut(pFile,"\tSource IP:\t %s\t", ipAddressSrc);
			pNetworkPcInfo[*nbPcInfo].osName = FingerPrinting(iphdr->ip_ttl,pFile);
			(*nbPcInfo)++;
			pNetworkPcInfo = (NetworkPcInfo*)realloc(pNetworkPcInfo, ((*nbPcInfo) + 1) * sizeof(NetworkPcInfo));
			if (pNetworkPcInfo == NULL)
				return FALSE;
		}
	}
	if (IS_PRIVATE_IP(ipAddressDst)) {
		int iDst;
		for (iDst = 0; iDst < *nbPcInfo && strcmp(pNetworkPcInfo[iDst].ipAddress, ipAddressDst) != 0; iDst++);
		if (iDst == *nbPcInfo) {
			pNetworkPcInfo[*nbPcInfo].ipAddress = (char*)calloc(IP_ADDRESS_SIZE + 1, 1);
			if (pNetworkPcInfo[*nbPcInfo].ipAddress == NULL)
				return FALSE;
			strcpy_s(pNetworkPcInfo[*nbPcInfo].ipAddress, IP_ADDRESS_SIZE, ipAddressDst);
			//pNetworkPcInfo[*nbPcInfo].osName = FingerPrinting(iphdr->ip_ttl);
			pNetworkPcInfo[*nbPcInfo].osName = OsUnknown;
			pNetworkPcInfo[*nbPcInfo].macAddress = NULL;
			printOut(pFile,"\tDestination IP:\t %s\n", ipAddressDst);
			(*nbPcInfo)++;
			pNetworkPcInfo = (NetworkPcInfo*)realloc(pNetworkPcInfo, ((*nbPcInfo) + 1) * sizeof(NetworkPcInfo));
			if (pNetworkPcInfo == NULL)
				return FALSE;
		}
	}

	*ppNetworkPcInfo = pNetworkPcInfo;
	return TRUE;
}

long CheckTimeSniffing(clock_t start, int timeSniffing) {
	return (double)(clock() - start) / CLOCKS_PER_SEC < timeSniffing;
}

BOOL StartSniffing(SOCKET sniffer, int timeSniffing, NetworkPcInfo** ppNetworkPcInfo, int* nbDetected, FILE* pFile) {
	int nbPcInfo = 0;
	clock_t start;
	int mangobyte;
	//char Buffer[PACKET_BUFFER_SIZE]; // heap alloc

	*ppNetworkPcInfo = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);
	if (*ppNetworkPcInfo == NULL)
		return FALSE;

	char* Buffer = (char*)HeapAlloc(GetProcessHeap(), 0, PACKET_BUFFER_SIZE);
	if (Buffer == NULL)
		return FALSE;

	mangobyte = recvfrom(sniffer, Buffer, PACKET_BUFFER_SIZE, 0, 0, 0);
	if (mangobyte <= 0)
		return FALSE;

	start = clock();
	while (mangobyte > 0 && CheckTimeSniffing(start, timeSniffing) && nbPcInfo < 255) {
		ProcessPacket(Buffer, mangobyte, ppNetworkPcInfo, &nbPcInfo,pFile);
		mangobyte = recvfrom(sniffer, Buffer, PACKET_BUFFER_SIZE, 0, 0, 0);
	}
	*nbDetected = nbPcInfo;
	if (mangobyte <= 0)
		printOut(pFile,"[x] recvfrom() failed.\n");

	if (!HeapFree(GetProcessHeap(), 0, Buffer)) {
		printOut(pFile,"[x] Call to HeapFree has failed (%u)\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


BOOL initSniffer(char* interfaceIp, SOCKET* sniffer, FILE* pFile) {
	SOCKADDR_IN dest;
	IN_ADDR addr;
	int in;

	char hostname[100];
	struct hostent* local;
	*sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (*sniffer == INVALID_SOCKET) {
		printOut(pFile,"[x] Failed to create raw socket.\n");
		return FALSE;
	}
	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printOut(pFile,"[x] Gethostname failed : %d\n", WSAGetLastError());
		return FALSE;
	}

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	if (local == NULL) {
		printOut(pFile,"[x] Gethostbyname failed: %d.\n", WSAGetLastError());
		return FALSE;
	}
	int i;
	if (local->h_addr_list[0] == 0){ 
		printOut(pFile,"[x] Interface not found !\n");
		return FALSE;
	}

	for (i = 0; local->h_addr_list[i] != 0; i++) {
		memcpy(&addr, local->h_addr_list[i], sizeof(IN_ADDR));
		if (strcmp(inet_ntoa(addr), interfaceIp) == 0)
			break;
	}
	if (strcmp(inet_ntoa(addr), interfaceIp) != 0) {
		printOut(pFile,"[x] The interface was not found !\n");
		return FALSE;
	}

	memset(&dest, 0, sizeof(SOCKADDR_IN));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[i], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	if (bind(*sniffer, (const SOCKADDR_IN*) &dest, sizeof(SOCKADDR_IN)) == SOCKET_ERROR) {
		printOut(pFile,"[x] bind(%s) failed.\n", inet_ntoa(addr));
		return FALSE;
	}
	int j = 1;
	if (WSAIoctl(*sniffer, SIO_RCVALL, &j, sizeof(int), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR) {
		printOut(pFile,"[x] WSAIoctl() failed.\n");
		return FALSE;
	}
	return TRUE;
}


BOOL PassifPacketSniffing(char* interfaceIp, int timeSniffing, NetworkPcInfo** networkPcInfo, int* nbDetected,FILE* pFile){
	SOCKET sniffer;

	printOut(pFile,"[i] Passif packet sniffing:\n");
	if (initSniffer(interfaceIp ,&sniffer,pFile)) {
		StartSniffing(sniffer, timeSniffing, networkPcInfo, nbDetected,pFile); // sniff for 30 second
		closesocket(sniffer);
		return TRUE;
	}
	return FALSE;
}