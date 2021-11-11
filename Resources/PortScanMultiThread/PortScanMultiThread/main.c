#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>


#pragma warning(disable:4996)  // for inet_addr


#define MAX_THREADS 3
#define BUF_SIZE 255

#pragma comment(lib, "Ws2_32.lib")

void ErrorHandler(LPTSTR lpszFunction) {
    // Retrieve the system error message for the last-error code.

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message.

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    // Free error-handling buffer allocations.

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}


BOOL initWSA() {
    WSADATA wsa;

    //printOut(pFile,"[i] Initialising Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[x] Failed. Error Code : %d", WSAGetLastError());
        return FALSE;
    }
    //printOut(pFile,"Initialised.\n");
    return TRUE;
}



typedef struct MyData {
    char ipAddress[16];
    int port;
} MYDATA, * PMYDATA;

#define PORT_FTP			21
#define PORT_SSH			22
#define PORT_TELNET			23
#define PORT_DNS			53
#define PORT_HTTP			80
#define PORT_KERBEROS		88
#define PORT_HTTP_TOMCAT	8009
#define PORT_HTTP_PROXY		8080
#define PORT_HTTP_OTHER		8180
#define PORT_NETBIOS_SSN	139
#define PORT_HTTPS			443
#define PORT_SMB			445
#define PORT_MSSQL			1433
#define PORT_ORACLEDB		1521
#define PORT_MYSQL			3306
#define PORT_POSTGRESQL		5432
#define PORT_WINRM			5985


#define NB_TAB_PORT			17

const int port[] = {
    PORT_FTP,
    PORT_SSH,
    PORT_TELNET,
    PORT_DNS,
    PORT_HTTP,
    PORT_KERBEROS,
    PORT_HTTP_TOMCAT,
    PORT_HTTP_PROXY,
    PORT_HTTP_OTHER,
    PORT_NETBIOS_SSN,
    PORT_HTTPS,
    PORT_SMB,
    PORT_MSSQL,
    PORT_ORACLEDB,
    PORT_MYSQL,
    PORT_POSTGRESQL,
    PORT_WINRM
};

int set_options(SOCKET fd) {
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 50;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) != SOCKET_ERROR; // if setsockopt == fail => return 0;
}

BOOL scanPortOpenTCP(char* dest_ip, int port) {
    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (tcp_sock == INVALID_SOCKET) {
        printf("[X] socket open failed %ld\n", GetLastError());
        closesocket(tcp_sock);
        return FALSE;
    } else {
        SOCKADDR_IN ssin;

        memset(&ssin, 0, sizeof(SOCKADDR_IN));
        ssin.sin_family = AF_INET;
        ssin.sin_port = htons(port);
        ssin.sin_addr.s_addr = inet_addr(dest_ip);

        if (!set_options(tcp_sock)) {
            printf("[X] Error setting socket options\n");
            closesocket(tcp_sock);
            return FALSE;
        }
        if (connect(tcp_sock, (struct sockaddr*)&ssin, sizeof(SOCKADDR_IN)) != SOCKET_ERROR) {
            closesocket(tcp_sock);
            return TRUE;
        }
    }
    closesocket(tcp_sock);
    return FALSE;
}

DWORD WINAPI MyThreadFunction(LPVOID lpParam) {
    HANDLE hStdout;
    PMYDATA pDataArray;

    TCHAR msgBuf[BUF_SIZE];
    size_t cchStringSize;
    DWORD dwChars;

    // Make sure there is a console to receive output results. 

    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE)
        return 1;

    // Cast the parameter to the correct data type.
    // The pointer is known to be valid because 
    // it was checked for NULL before the thread was created.

    pDataArray = (PMYDATA)lpParam;

    // Print the parameter values using thread-safe functions.

    BOOL isOpen = scanPortOpenTCP(pDataArray->ipAddress, pDataArray->port);

    StringCchPrintf(msgBuf, BUF_SIZE, TEXT("Port %i is %s\n"),
        pDataArray->port, isOpen ? L"open":L"close");
    StringCchLength(msgBuf, BUF_SIZE, &cchStringSize);
    WriteConsole(hStdout, msgBuf, (DWORD)cchStringSize, &dwChars, NULL);

    return 0;
}

int main() {
    PMYDATA pDataArray[NB_TAB_PORT];
    DWORD   dwThreadIdArray[NB_TAB_PORT];
    HANDLE  hThreadArray[NB_TAB_PORT];

    initWSA();

    // Create MAX_THREADS worker threads.
    for (int i = 0; i < NB_TAB_PORT; i++) {
        // Allocate memory for thread data.

        pDataArray[i] = (PMYDATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
            sizeof(MYDATA));

        if (pDataArray[i] == NULL) {
            // If the array allocation fails, the system is out of memory
            // so there is no point in trying to print an error message.
            // Just terminate execution.
            ExitProcess(2);
        }

        // Generate unique data for each thread to work with.

        strcpy_s(pDataArray[i]->ipAddress,16,"192.168.59.79");
        pDataArray[i]->port = port[i];

        // Create the thread to begin execution on its own.

        hThreadArray[i] = CreateThread(
            NULL,                   // default security attributes
            0,                      // use default stack size  
            MyThreadFunction,       // thread function name
            pDataArray[i],          // argument to thread function 
            0,                      // use default creation flags 
            &dwThreadIdArray[i]);   // returns the thread identifier 


        // Check the return value for success.
        // If CreateThread fails, terminate execution. 
        // This will automatically clean up threads and memory. 

        if (hThreadArray[i] == NULL) {
            ErrorHandler(TEXT("CreateThread"));
            ExitProcess(3);
        }
    } // End of main thread creation loop.

    // Wait until all threads have terminated.

    WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);

    // Close all thread handles and free memory allocations.

    for (int i = 0; i < MAX_THREADS; i++) {
        CloseHandle(hThreadArray[i]);
        if (pDataArray[i] != NULL) {
            HeapFree(GetProcessHeap(), 0, pDataArray[i]);
            pDataArray[i] = NULL;    // Ensure address is not reused.
        }
    }

    system("pause");
    return 0;
}