#include <windows.h>
#include <stdio.h>
#include <winhttp.h>
#include "Tools.h"

#define GET_REQUEST_SIZE    1000

#pragma comment(lib,"Winhttp.lib")
#pragma warning(disable:4996) //inet_addr


BOOL GetHTTPSserver(char* ipAddress, int port, char* serverResponce, FILE* pFile) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    wchar_t  wIpAddressw[100];
    swprintf(wIpAddressw, 100, L"%hs", ipAddress);

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printOut(pFile,"\t[X] WinHttpOpen:Error %d has occurred.", GetLastError());
        return FALSE;
    }

    // Specify an HTTP server.
    hConnect = WinHttpConnect(hSession, wIpAddressw, port, 0);
    if (!hConnect) {
        printOut(pFile,"\t[X] WinHttpConnect:Error %d has occurred.", GetLastError());
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", L"HTTP/1.1", WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        printOut(pFile,"\t[X] WinHttpOpenRequest:Error %d has occurred.", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD secureflags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    BOOL bResult = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&secureflags, sizeof(secureflags));
    if (!bResult) {
        printOut(pFile,"\t[X] WinHttpSetOption:Error %d has occurred.", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD dwSize = sizeof(DWORD);

            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL,
                &dwSize, WINHTTP_NO_HEADER_INDEX);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                WCHAR* lpOutBuffer = (WCHAR*)calloc(dwSize, 1);
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                    lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
                    sprintf_s(serverResponce, GET_REQUEST_SIZE, "%ws", (WCHAR*)lpOutBuffer);
                    free(lpOutBuffer);
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return TRUE;
                }
            }
        } else
            printOut(pFile,"\t[X] WinHttpReceiveResponse:Error %d has occurred.", GetLastError());
    } else
        printOut(pFile,"\t[X] WinHttpSendRequest:Error %d has occurred.", GetLastError());

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return FALSE;
}