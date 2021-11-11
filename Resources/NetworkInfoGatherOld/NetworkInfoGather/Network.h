
#pragma once
#include "portList.h"
#include "NetDiscovery.h"

#ifndef NETWORK_HEADER_H
#define NETWORK_HEADER_H

#define MAX_NB_ADAPTER	50

#define MASK_NB_BYTE	4

#define OCTE_MAX		0xFF
#define OCTE_SIZE		8
#define BYTE_SIZE		4
#define IP_SIZE_CHAR	16
#define MASK_SIZE_CHAR	16

const int port[NB_TAB_PORT];

BOOL initWSA(FILE* pFile);

#endif