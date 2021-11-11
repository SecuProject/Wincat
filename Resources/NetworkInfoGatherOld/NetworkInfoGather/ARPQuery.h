#pragma once

#ifndef ARP_QUERY_H
#define ARP_QUERY_H

BOOL ARPdiscovery(int maskSizeInt, NetworkPcInfo** ptrNetworkPcInfo, INT32 ipAddressBc, int* nbDetected, FILE* pFile);

#endif