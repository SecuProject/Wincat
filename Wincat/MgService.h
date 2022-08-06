#pragma once

#ifndef MG_SERVICE_HEADER_H
#define MG_SERVICE_HEADER_H

#define SERVICE_ERROR		-1
#define SERVICE_NOT_RUNNING 0

#include "LoadAPI.h"

BOOL CheckServiceStatusConfig(Kernel32_API kernal32,Advapi32_API advapi32, char* szSvcName, BOOL isDebug);

int CheckServerStatus(Advapi32_API advapi32, char* serviceName);
int StartServer(Advapi32_API advapi32, char* serviceName);


#endif