#include <windows.h>
#include <stdio.h>

#include "NetDiscovery.h"
#include "ICMP.h"
#include "ARPQuery.h"
#include "ARPTable.h"
#include "GetMacVendor.h"
#include "PassifPacketSniffing.h"
#include "MgArguments.h"
#include "Tools.h"


BOOL NetDiscovery(Arguments listAgrument, INT32 ipRangeInt32, int maskSizeInt,char* localIP, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile) {
	switch (listAgrument.typeOfScan) {
// ------------------------ Passive Attack  ------------------------
	case Passif_Scan:
		if (getARPTable(networkPcInfo, nbDetected, ipRangeInt32,pFile)) {
			getMacVendor(*networkPcInfo, *nbDetected);
			for (int i = 0; i < *nbDetected; i++)
				printOut(listAgrument.ouputFile,"\t[%s] \t%s - %s\n", (*networkPcInfo)[i].ipAddress, (*networkPcInfo)[i].macAddress, (*networkPcInfo)[i].vendorName);
			return *nbDetected > 0;
		}
	case Passif_Packet_Sniffing:
		return PassifPacketSniffing(localIP, 5, networkPcInfo, nbDetected, listAgrument.ouputFile); // 30
// ------------------------ Active Attack ------------------------
	case ICMP_Scan:
		return ICMPdiscovery(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile);
	case ARP_Scan:
		return ARPdiscovery(maskSizeInt, networkPcInfo, ipRangeInt32, nbDetected, pFile) && getMacVendor(*networkPcInfo, *nbDetected);
	default:
		break;
	}
	return FALSE;
}