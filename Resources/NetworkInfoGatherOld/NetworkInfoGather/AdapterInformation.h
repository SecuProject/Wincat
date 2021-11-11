#pragma once

#ifndef ADAPTER_INFORMATION_HEADER_H
#define ADAPTER_INFORMATION_HEADER_H

#define MAX_BUFFER		128

typedef struct {
	char localIP[MAX_BUFFER];
	char GateWayIp[MAX_BUFFER];
	char networkMask[MAX_BUFFER];
	int InterfaceIndex;
}ADAPTER_INFO;


INT32 ipCalucation(char* localIP, char* networkMask, int* maskSizeInt);
int getAdapterkInfo(ADAPTER_INFO* adapterInfo, FILE* pFile);
INT32 IPToUInt(char* ip);

#endif