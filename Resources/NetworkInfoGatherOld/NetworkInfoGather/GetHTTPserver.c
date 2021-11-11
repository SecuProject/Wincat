#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#include "ToolsHTTP.h"
#include "Tools.h"

#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

BOOL GetHTTPserver(char* ipAddress, int port, char* serverResponce, FILE* pFile) {
    SOCKET Socket;
    SOCKADDR_IN SockAddr;

    int requestSize;
    int sendSize; 

    char getRequest[GET_REQUEST_SIZE];
    char* request =
        "GET / HTTP/1.1\r\n"
        "User-Agent: %s\r\n" // Add rand + list
        "Host: %s\r\n"
        "Connection: close\r\n\r\n";

    Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SockAddr.sin_port = htons(port);
    SockAddr.sin_family = AF_INET;
    SockAddr.sin_addr.s_addr = inet_addr(ipAddress);

    if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0) {
        printOut(pFile,"\t[X] Could not connect to the web server.\n");
        return FALSE;
    }
    requestSize = sprintf_s(getRequest, GET_REQUEST_SIZE, request, userAgentList[rand() % 5], ipAddress);
    if (requestSize <= 0) {
        printOut(pFile,"\t[X] Generate Get request failed.\n");
        closesocket(Socket);
        return FALSE;
    }
    sendSize = send(Socket, getRequest, requestSize, 0);
    if (sendSize <= 0) {
        printOut(pFile,"\t[X] Send request failed.\n");
        closesocket(Socket);
        return FALSE;
    }
    if (sendSize != requestSize)
        printOut(pFile,"\t[!] Send request size not match !\n");
    int nDataLength = recv(Socket, serverResponce, GET_REQUEST_SIZE -1 , 0);
    if (nDataLength <= 0) {
        //printOut(pFile,"\t[X] Could not connect.\n");
        closesocket(Socket);
        return FALSE;
    }
    serverResponce[nDataLength] = 0x00;
    closesocket(Socket);
    return TRUE;
}