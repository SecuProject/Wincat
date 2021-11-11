#pragma once

#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

// BOOL startPinging(char* ipAddress);

BOOL ICMPdiscovery(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile);

#endif