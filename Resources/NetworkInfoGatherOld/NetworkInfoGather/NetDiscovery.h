#pragma once
#include "portList.h"


#ifndef NET_DISCOVERY_HEADER_H
#define NET_DISCOVERY_HEADER_H
#include "MgArguments.h"

typedef enum {
	OsUnknown = 0,
	OsWindows = 1,
	OsLinux = 2,
	OsMac = 3,
	OsDSB = 4,
	OsCisco = 5
}EnumOS;



//typedef struct {
//	char* typeOS;
//	int version;
//	int port;
//}FingerPrintInfo;

typedef struct {
	char Name[33];
	BOOL isGroup;
}NETBIOS_R_M_N_TAB;


typedef struct {
	NETBIOS_R_M_N_TAB* netBIOSRemoteMachineNameTab;
	int nbNetBIOSRemoteMachineNameTab;

	//unsigned char macAddress[6];
	char macAddress[40];
}NETBIOS_Info;

typedef struct {
	int portNumber;
	char banner[50];
}PORT_INFO;

typedef struct {
	char* ipAddress;
	char* macAddress;
	char* vendorName;

	int version;
	PORT_INFO port[NB_TAB_PORT];
	int nbOpenPort;


	EnumOS osName;

	NETBIOS_Info* NetbiosInfo;
	BOOL isNetbiosInfo;


	//FingerPrintInfo fPInfo[6]; // as a ptr !!!
	//int nbfingerPrintInfo;
}NetworkPcInfo;

BOOL NetDiscovery(Arguments listAgrument, INT32 ipRangeInt32, int maskSizeInt, char* localIP, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile);

#endif