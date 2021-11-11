#pragma once

#ifndef NETWORK_HEADER_H
#define NETWORK_HEADER_H

#define PHYSUCAL_ADDRESS_LENGTH	6
#define IP_ADDRESS_LENGTH		16


BOOL getARPTable(NetworkPcInfo** ptrArpTable, int* arpTableSize, INT32 ipRangeInt32, FILE* pFile);

#endif