#include <windows.h>
#include <stdio.h>

#include "ToolsHTTP.h"
#include "GetHTTPserver.h"
#include "GetHTTPSserver.h"
#include "Tools.h"

int EnumHTTP(char* ipAddress, int port, char* banner, int bufferSize, FILE* pFile) {
    char serverResponce[GET_REQUEST_SIZE];
    if (GetHTTPserver(ipAddress, port, serverResponce,pFile)) {
        if (GetHTTPserverVersion(serverResponce, banner, bufferSize)) {
            printOut(pFile,"\t[HTTP] Port %i Banner %s\n", port, banner);
            return TRUE;
        }
    }
    printOut(pFile,"\t[HTTP] Port %i Error\n", port);
    return FALSE;
}
int EnumHTTPS(char* ipAddress, int port, char* banner, int bufferSize, FILE* pFile) {
    char serverResponce[GET_REQUEST_SIZE];
    if (GetHTTPSserver(ipAddress, port, serverResponce,pFile)) {
        if (GetHTTPserverVersion(serverResponce, banner, bufferSize)) {
            printOut(pFile,"\t[HTTPS] Port %i Banner %s\n", port, banner);
            return TRUE;
        }
    }
    printOut(pFile,"\t[HTTPS] Port %i Error\n", port);
    return FALSE;
}

/*
int EnumHTTP(char* ipAddress, int port, char* banner, int bufferSize) {
    char serverResponce[GET_REQUEST_SIZE];
    //int serverReturnCode;
    //char serverVersion[SERVER_VERSION_SIZE];

    //printOut(pFile,"[*] Get %s HTTP %i Website !\n", ipAddress, port);
    if (GetHTTPserver(ipAddress, port, serverResponce)) {
        //printOut(pFile,"%s\n", serverResponce);
        //if (GetHTTPReturnCode(serverResponce, &serverReturnCode)) {
        //    //printOut(pFile,"\t[i] Return Code '%i'\n", serverReturnCode);
        //}
        if (GetHTTPserverVersion(serverResponce, banner, bufferSize)) {
            //printOut(pFile,"\t[i] Server Version '%s'\n", banner);
        }
        printOut(pFile,"\t[HTTP] Port %i Banner %s\n", port, banner);
        return TRUE;
    }
    printOut(pFile,"\t[HTTPS] %i Error\n", port);
    return FALSE;
}
int EnumHTTPS(char* ipAddress,int port, char* banner, int bufferSize) {
    char serverResponce[GET_REQUEST_SIZE];
    //int serverReturnCode;
    //char serverVersion[SERVER_VERSION_SIZE];
    //printOut(pFile,"[*] Get %s HTTPS %i Website !\n", ipAddress, port);
    if (GetHTTPSserver(ipAddress, port, serverResponce)) {
        //printOut(pFile,"%s\n", serverResponce);
        //if (GetHTTPReturnCode(serverResponce, &serverReturnCode)) {
        //    //printOut(pFile,"[i] Return Code '%i'\n", serverReturnCode);
        //}
        if (GetHTTPserverVersion(serverResponce, banner, bufferSize)) {
            //printOut(pFile,"[i] Server Version '%s'\n", banner);
        }
        printOut(pFile,"\t[HTTPS] Banner %s\n", banner);
        return TRUE;
    }
    printOut(pFile,"\t[HTTPS] %i Error\n", port);
    return FALSE;
}*/