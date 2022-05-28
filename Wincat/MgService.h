#pragma once

#ifndef MG_SERVICE_HEADER_H
#define MG_SERVICE_HEADER_H

#define SERVICE_ERROR		-1
#define SERVICE_NOT_RUNNING 0

BOOL CheckServiceStatusConfig(char* szSvcName, BOOL isDebug);

int CheckServerStatus(char* serviceName);
int StartServer(char* serviceName);


#endif