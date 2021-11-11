#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "Network.h"

#define MAX_LENGTH_LINE 128
#define MAX_MAC_LENGTH 8


BOOL cutString(char* lineBuffer, char*  macAddress, char*  vendorName) {
	char * pch;
	char *next_token = NULL;

	pch = strtok_s(lineBuffer, "#", &next_token);
	if (pch != NULL) {
		strcpy_s(macAddress, MAX_MAC_LENGTH + 1, pch);
		pch = strtok_s(NULL, "\n", &next_token);
		if (pch != NULL) {
			strcpy_s(vendorName, MAX_LENGTH_LINE, pch);
			return TRUE;
		}
	}
	return FALSE;
}


int getMacDB(char* macAddressSearch, NetworkPcInfo* networkPcInfo) {
	FILE * pFile;
	BOOL returnValue = FALSE;

	if (fopen_s(&pFile, "mac.db", "r") != 0)
		return -1;
	else {
		char* macAddress = (char*)calloc(MAX_MAC_LENGTH + 1, 1);
		if (macAddress != NULL) {
			char* vendorName = (char*)calloc(MAX_LENGTH_LINE, 1);
			if (vendorName != NULL) {
				char* lineBuffer = (char*)calloc(MAX_LENGTH_LINE, 1);
				if (lineBuffer != NULL) {
					while (fgets(lineBuffer, MAX_LENGTH_LINE, pFile) != NULL && cutString(lineBuffer, macAddress, vendorName) && strcmp(macAddressSearch, macAddress) != 0);
					BOOL vendorNameFound = strcmp(macAddressSearch, macAddress) == 0;
					int sizeVendorNameBuffer = (vendorNameFound? (int)strlen(vendorName):6) + 1;

					networkPcInfo->vendorName = (char*)calloc(sizeVendorNameBuffer, 1);
					if (networkPcInfo->vendorName != NULL) {
						strcpy_s(networkPcInfo->vendorName, sizeVendorNameBuffer, vendorNameFound ? vendorName:"UNKNOW");
						returnValue = TRUE;
					}
					free(lineBuffer);
				}
				free(vendorName);
			}
			free(macAddress);
		}
		fclose(pFile);
	}
	return returnValue;
}



int getVendorFormMac(NetworkPcInfo* networkPcInfo) {
	int returnValue = FALSE;

	char* macAddressSearch = (char*)calloc(MAX_MAC_LENGTH + 1, 1);
	if (macAddressSearch != NULL) {
		strncpy_s(macAddressSearch, MAX_MAC_LENGTH + 1, networkPcInfo->macAddress, MAX_MAC_LENGTH);
		returnValue = getMacDB(macAddressSearch, networkPcInfo);
		free(macAddressSearch);
	}
	return returnValue;
}




BOOL getMacVendor(NetworkPcInfo* networkPcInfo,int nbDetected) {
	BOOL returnValue = TRUE;

	for (int i = 0; i < nbDetected && returnValue; i++)
		returnValue = getVendorFormMac(&(networkPcInfo[i])) != -1;
	return returnValue;
}
