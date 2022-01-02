#pragma once

#ifndef PIPE_SERVER_HEADER_H
#define PIPE_SERVER_HEADER_H

#define BUFSIZE 512
#define MATCH(string1,string2) (strcmp(string1, string2) == 0)
#define MATCH_S(string1,string2,size) (strncmp(string1, string2,size) == 0)

typedef struct{
    char ipAddress[16];//IP_ADDRESS_LEN
    UINT port;
    BOOL exploitStatus;
    char* pathExeToRun;
}PipeDataStruct;


BOOL AuthClient(HANDLE hPipe, const char* password, char* pchRequest, char* pchReply);
BOOL HeapAllocF(HANDLE hHeap, char** pchRequest, char** pchReply);
BOOL GetAnswerToRequest(PipeDataStruct* pipeDataStruct, char* pchRequest, char* pchReply, LPDWORD pchBytes);
BOOL ServerReplay(HANDLE hPipe, PipeDataStruct* pipeDataStruct, char* pchRequest, char* pchReply);
BOOL SendInfoPipe(PipeDataStruct* pipeDataStruct, const char* lpszPipename, const char* password);

#endif