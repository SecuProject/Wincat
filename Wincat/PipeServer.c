#include <windows.h> 
#include <stdio.h>

#include "PipeServer.h"
#include "Message.h"

BOOL AuthClient(HANDLE hPipe, const char* password, char* pchRequest, char* pchReply){
    size_t passwordSize = strlen(password);
    BOOL authValid = FALSE;

    while (!authValid){
        DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;

        if (!ReadFile(hPipe, pchRequest, BUFSIZE, &cbBytesRead, NULL) || cbBytesRead == 0){
            if (GetLastError() == ERROR_BROKEN_PIPE)
                printMsg(STATUS_WARNING2, LEVEL_DEFAULT, "Client disconnected.\n");
            else
                printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "ReadFile failed");
            return FALSE;
        }
        if (MATCH_S(pchRequest, password, passwordSize)){
            authValid = TRUE;
            strcpy_s(pchReply, BUFSIZE, "AUTH_OK");
        } else{
            strcpy_s(pchReply, BUFSIZE, "AUTH_FAIL");
        }
        cbReplyBytes = (DWORD)(strlen(pchReply) + 1);


        if (!WriteFile(hPipe, pchReply, cbReplyBytes, &cbWritten, NULL) || cbReplyBytes != cbWritten){
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "WriteFile failed");
            return FALSE;
        }
    }
    return TRUE;
}

BOOL HeapAllocF(HANDLE hHeap, char** pchRequest, char** pchReply){
    *pchRequest = (char*)HeapAlloc(hHeap, 0, BUFSIZE);
    if (pchRequest == NULL){
        return FALSE;
    }
    *pchReply = (char*)HeapAlloc(hHeap, 0, BUFSIZE);
    if (pchReply == NULL){
        HeapFree(hHeap, 0, pchRequest);
        return FALSE;
    }
    return TRUE;
}

BOOL GetAnswerToRequest(PipeDataStruct* pipeDataStruct, char* pchRequest, char* pchReply, LPDWORD pchBytes){
    char* setting = (char*)malloc(BUFSIZE);
    if (setting != NULL){
        char* value = (char*)malloc(BUFSIZE);
        if (value != NULL){
            int nbData = sscanf_s(pchRequest, "%s %s", setting, BUFSIZE, value, BUFSIZE);
            switch (nbData){
            case 1:
                printMsg(STATUS_OK2, LEVEL_DEFAULT, "Client> \"%s\"\n", setting);
                if (MATCH(pchRequest, "GET_IP_ADDRESS")){
                    strcpy_s(pchReply, BUFSIZE, pipeDataStruct->ipAddress);
                } else if (MATCH(pchRequest, "GET_PORT")){
                    sprintf_s(pchReply, BUFSIZE, "%i", pipeDataStruct->port);
                } else if (MATCH(pchRequest, "GET_EXE_PATH")){
                    strcpy_s(pchReply, BUFSIZE, pipeDataStruct->pathExeToRun);
                } else{
                    strcpy_s(pchReply, BUFSIZE, "???");
                }
                *pchBytes = (DWORD)(strlen(pchReply) + 1);
                free(value);
                free(setting);
                return TRUE;
            case 2:
                printMsg(STATUS_OK2, LEVEL_DEFAULT, "Client SET> \"%s\"\n", value);
                if (MATCH(setting, "SET_IP_ADDRESS")){
                    strcpy_s(pchReply, BUFSIZE, "ACK");
                    strcpy_s(pipeDataStruct->ipAddress, IP_ADDRESS_LEN, value);
                } else if (MATCH(setting, "SET_GET_PORT")){
                    strcpy_s(pchReply, BUFSIZE, "ACK");
                    pipeDataStruct->port = atoi(value);
                } else if (MATCH(setting, "STATUS")){
                    strcpy_s(pchReply, BUFSIZE, "ACK");
                    if(value[0] == '1')
                        pipeDataStruct->exploitStatus = TRUE;
                    else
                        pipeDataStruct->exploitStatus = FALSE;
                } else{
                    strcpy_s(pchReply, BUFSIZE, "???");
                }
                *pchBytes = (DWORD)(strlen(pchReply) + 1);
                free(value);
                free(setting);
                return TRUE;
            default:
                break;
            }
            free(value);
        }
        free(setting);
    }
    return FALSE;
}
BOOL ServerReplay(HANDLE hPipe, PipeDataStruct* pipeDataStruct, char* pchRequest, char* pchReply){
    DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
    BOOL fSuccess = ReadFile(hPipe, pchRequest, BUFSIZE, &cbBytesRead, NULL);
    if (!fSuccess || cbBytesRead == 0){
        if (GetLastError() == ERROR_BROKEN_PIPE)
            printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Client disconnected.\n");
        else
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "ReadFile failed");
        return FALSE;
    }
    // Process the incoming message.
    GetAnswerToRequest(pipeDataStruct, pchRequest, pchReply, &cbReplyBytes);

    // Write the reply to the pipe. 
    fSuccess = WriteFile(hPipe, pchReply, cbReplyBytes, &cbWritten, NULL);
    if (!fSuccess || cbReplyBytes != cbWritten){
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "WriteFile failed");
        return FALSE;
    }
    return TRUE;
}
BOOL SendInfoPipe(PipeDataStruct* pipeDataStruct, const char* lpszPipename, const char* password){
    HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;

    printf("\n[-] Pipe Server: Waiting client connection on %s\n", lpszPipename);

    DWORD dwPipeMode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT;

    // PIPE_WAIT ? PIPE_NOWAIT
    hPipe = CreateNamedPipeA(lpszPipename, PIPE_ACCESS_DUPLEX, dwPipeMode, PIPE_UNLIMITED_INSTANCES, BUFSIZE, BUFSIZE, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE){
        if (ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)){
            HANDLE hHeap = GetProcessHeap();
            char* pchRequest = NULL, * pchReply = NULL;
            if (HeapAllocF(hHeap, &pchRequest, &pchReply)){
                //DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;

                printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Client connected.\n");
                if (!AuthClient(hPipe, password, pchRequest, pchReply)){
                    return FALSE;
                }
                printMsg(STATUS_OK, LEVEL_DEFAULT, "Client authenticate successfully !\n");

                // Loop until done reading
                while (ServerReplay(hPipe, pipeDataStruct, pchRequest, pchReply));


                FlushFileBuffers(hPipe);
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);

                HeapFree(hHeap, 0, pchRequest);
                HeapFree(hHeap, 0, pchReply);
            }
        }else
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "ConnectNamedPipe ERROR_IO_PENDING ");
    } else
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "CreateNamedPipe failed");
    return TRUE;
}