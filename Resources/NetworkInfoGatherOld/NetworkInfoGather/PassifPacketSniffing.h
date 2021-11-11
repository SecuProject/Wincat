#pragma once
#ifndef PASSIF_PACKET_SNIFFING_HEADER_H
#define PASSIF_PACKET_SNIFFING_HEADER_H
BOOL PassifPacketSniffing(char* interfaceIp, int timeSniffing, NetworkPcInfo** networkPcInfo, int* nbDetected, FILE* pFile);

#endif