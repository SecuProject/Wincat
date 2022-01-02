#include <windows.h> 
#include <stdio.h> 

#include "PipeServer.h"


int main(VOID){
    PipeDataStruct pipeDataStruct;
    const char* lpszPipename = "\\\\.\\pipe\\mynamedpipeHigh";
    const char* password = "SeMf523hqsXxaAy8bUaCRPbW62UT7R4ybXqJZjNVDnKya9ggXJ6UjKku77mB";

    SendInfoPipe(&pipeDataStruct, lpszPipename, password);

    printf("[-] Result:\n");
    printf("\t[+] Ip address: %s\n", pipeDataStruct.ipAddress);
    printf("\t[+] Port: %i\n", pipeDataStruct.port);

    system("pause");
    return 0;
}