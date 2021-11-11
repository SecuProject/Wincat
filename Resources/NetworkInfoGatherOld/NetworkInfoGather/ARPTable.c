
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma warning(disable:4996)

#include "Network.h"
#include "AdapterInformation.h"
#include "Tools.h"


#define PHYSUCAL_ADDRESS_LENGTH		6
#define PHYSUCAL_ADDRESS_SIZE		PHYSUCAL_ADDRESS_LENGTH * 3 + 5 
// '-' * 5 


#define IP_ADDRESS_LENGTH			16

#define CHECK_IP_STATE(value)	(value == NlnsReachable || value == NlnsStale)


BOOL isDuplicate(NetworkPcInfo* arpTable,int arpTableSize,char* ipAddress) {
	for (int j = 0; j < arpTableSize; j++) {
		if (strcmp(arpTable[j].ipAddress, ipAddress) == 0)
			return TRUE;
	}
	return FALSE;
}



BOOL isNetworkRange(char* ipAddress, INT32 ipRangeInt32) {
	INT32 ipAddressInt = IPToUInt(ipAddress);
	return ((ipAddressInt - ipRangeInt32) < 256 && (ipAddressInt - ipRangeInt32) >= 0);
}

BOOL getARPTable(NetworkPcInfo** ptrArpTable, int* arpTableSize, INT32 ipRangeInt32, FILE* pFile) {
	PMIB_IPNET_TABLE2 pipTable = NULL;
	int status = GetIpNetTable2(AF_INET, &pipTable);
	
	printOut(pFile,"[i] ARP Table discovery:\n");
	if (status != NO_ERROR) {
		printOut(pFile,"[x] GetIpNetTable for IPv4 table returned error: %i\n", status);
		return FALSE;
	} else {
		NetworkPcInfo* arpTable = (NetworkPcInfo*)calloc(sizeof(NetworkPcInfo), 1);

		if (arpTable == NULL)
			return FALSE;

		for (int i = 0; (unsigned)i < pipTable->NumEntries; i++) {
			if (CHECK_IP_STATE(pipTable->Table[i].State) && pipTable->Table[i].PhysicalAddressLength == PHYSUCAL_ADDRESS_LENGTH) {
				if (!isDuplicate(arpTable, *arpTableSize, inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr)) && 
					isNetworkRange(inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr), ipRangeInt32)) {
					// Check Network
					arpTable[*arpTableSize].ipAddress = (char*)calloc(IP_ADDRESS_LENGTH + 1, 1);
					if (arpTable[*arpTableSize].ipAddress == NULL)
						return FALSE;
					strcpy_s(arpTable[*arpTableSize].ipAddress, IP_ADDRESS_LENGTH + 1, inet_ntoa(pipTable->Table[i].Address.Ipv4.sin_addr));


					arpTable[*arpTableSize].macAddress = (char*)calloc(PHYSUCAL_ADDRESS_LENGTH * 3 + 5 + 1, 1);
					if (arpTable[*arpTableSize].macAddress == NULL)
						return FALSE;
					for (int j = 0; j < PHYSUCAL_ADDRESS_LENGTH; j++)
						sprintf_s(arpTable[*arpTableSize].macAddress + (3 * j), PHYSUCAL_ADDRESS_SIZE - (3 * (int)j / 2) + 1, (j == (PHYSUCAL_ADDRESS_LENGTH - 1)) ? "%.2X" : "%.2X-", (int)pipTable->Table[i].PhysicalAddress[j]);


					arpTable = (NetworkPcInfo*)realloc(arpTable, ((*arpTableSize) + 2) * sizeof(NetworkPcInfo));
					if (arpTable == NULL)
						return FALSE;

					(*arpTableSize)++;
				}
			}
		}
		*(ptrArpTable) = arpTable;
	
	}
	FreeMibTable(pipTable);
	pipTable = NULL;
	return TRUE;
}

