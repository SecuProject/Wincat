

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <time.h>

#include "MgDownload.h"
#include "Message.h"

#pragma comment (lib, "Wininet.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)           // inet_addr & gethostbyname

#define FILE_BUFFER_SIZE 4096 * 1024
#define IP_ADDRESS_SIZE     16

const char* userAgentList[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
    "Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
};

BOOL InitMgDownload() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MsgError("Fail to InitWSAStartup: %ld\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}
BOOL CleanMgDownload() {
    return WSACleanup();
}

BOOL GetIp(const char* url, char* ipAddress) {
    struct hostent* he = gethostbyname(url);
    if (he == NULL) {
        switch (h_errno) {
        case HOST_NOT_FOUND:
            MsgError2("The host was not found (%ld).\n", stderr);
            break;
        case NO_ADDRESS:
            MsgError2("The name is valid but it has no address (%ld).\n", stderr);
            break;
        case NO_RECOVERY:
            MsgError2("A non-recoverable name server error occurred (%ld).\n", stderr);
            break;
        case TRY_AGAIN:
            MsgError2("The name server is temporarily unavailable (%ld).\n", stderr);
            break;
        default:
            MsgError2("Fail to get hostname: %ld\n", h_errno);
        }
        return FALSE;
    }
    strcpy_s(ipAddress, IP_ADDRESS_SIZE, inet_ntoa(*((struct in_addr*)he->h_addr_list[0])));
    return TRUE;
}


BOOL TestCreateFile(const char* filePath, const char* filename, const char* fileBuffer, UINT fileBufferSize) {
    HANDLE pFile;
    DWORD dwBytesWritten;
    size_t fileFullPathSize = strlen(filePath) + strlen(filename) + 1 + 1;
    char* fileFullPath = (char*)malloc(fileFullPathSize);
    if (fileFullPath != NULL) {
        sprintf_s(fileFullPath, fileFullPathSize, "%s\\%s", filePath, filename);
        pFile = CreateFileA(fileFullPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (pFile != INVALID_HANDLE_VALUE) {
            if (WriteFile(pFile, fileBuffer, fileBufferSize, &dwBytesWritten, NULL)) {
                CloseHandle(pFile);
                free(fileFullPath);
                return TRUE;
            }
            MsgBlock2("%s - WriteFile failed\n", filePath);
            CloseHandle(pFile);
        }
        else
            MsgBlock2("%s - CreateFileA failed\n", filePath);
        free(fileFullPath);
    }
    else
        MsgBlock2("%s - VirtualAlloc failed\n", filePath);
    return FALSE;
}
BOOL TestReadFile(const char* filePath) {
    HANDLE pFile;
    DWORD dwBytesRead;
    pFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (pFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(pFile, NULL);
        char* fileBuffer = (char*)VirtualAlloc(0, fileSize, MEM_COMMIT, PAGE_READWRITE);
        if (fileBuffer != NULL) {
            if (ReadFile(pFile, fileBuffer, fileSize, &dwBytesRead, NULL)) {
                CloseHandle(pFile);
                VirtualFree(fileBuffer, 0, MEM_RELEASE);
                return TRUE;
            }
            MsgBlock2("%s - ReadFile failed\n", filePath);
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
        }
        else
            MsgBlock2("%s - VirtualAlloc failed\n", filePath);
        CloseHandle(pFile);
    }
    else
        MsgBlock2("%s - Open file failed\n", filePath);
    return FALSE;
}

BOOL MainMgDownload(const char* url, const char* urlPath, const char* filePath, DWORD* fileSize, BOOL isHTTPS) {
    HINTERNET hInternetOpen;
    HINTERNET hInternetConnect;
    HINTERNET hInternetRequest;

    int userAgentIndex;

    DWORD flags = isHTTPS ? (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA) : INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT;
    const char method[] = "GET";
    const char* userAgentList[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
        "Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
    };

    srand((UINT)time(NULL));
    userAgentIndex = rand() % 5;

    hInternetOpen = InternetOpenA(userAgentList[userAgentIndex], INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternetOpen == NULL) {
        MsgBlock2("%s - InternetOpen failed\n", filePath + 1);
        return FALSE;
    }

    if (isHTTPS)
        hInternetConnect = InternetConnectA(hInternetOpen, url, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    else
        hInternetConnect = InternetConnectA(hInternetOpen, url, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

    if (hInternetConnect == NULL) {
        MsgBlock2("%s - InternetConnect failed\n", filePath + 1);
        return FALSE;
    }

    hInternetRequest = HttpOpenRequestA(hInternetConnect, method, urlPath, NULL, NULL, NULL, flags, 0);
    if (hInternetRequest == NULL) {
        MsgBlock2("%s - HttpOpenRequest failed\n", filePath + 1);
        return FALSE;
    }

    if (isHTTPS) {
        DWORD dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
        if (!InternetSetOptionA(hInternetRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(DWORD))) {
            MsgBlock2("%s - InternetSetOption failed\n", filePath + 1);
            return FALSE;
        }
    }

    if (!HttpSendRequestA(hInternetRequest, NULL, 0, NULL, 0)) {
        MsgBlock2("%s - HttpSendRequest failed\n", filePath + 1);
        return FALSE;
    }

    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
    if (!HttpQueryInfoA(hInternetRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL)) {
        MsgBlock2("%s - HttpQueryInfoA failed\n", filePath + 1);
        return FALSE;
    }
    if (HTTP_STATUS_OK == statusCode) {
        char* fileBuffer = (char*)VirtualAlloc(0, FILE_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE);
        if (fileBuffer != NULL) {
            DWORD dwBytesRead = 0;
            BOOL bKeepReading = InternetReadFile(hInternetRequest, fileBuffer, 4096, &dwBytesRead);
            DWORD dwBytesWritten = dwBytesRead;


            while (bKeepReading && dwBytesRead != 0 && dwBytesWritten + 4096 < FILE_BUFFER_SIZE) {
                bKeepReading = InternetReadFile(hInternetRequest, (fileBuffer + dwBytesWritten), 4096, &dwBytesRead);
                dwBytesWritten += dwBytesRead;
            }
            InternetCloseHandle(hInternetRequest);
            InternetCloseHandle(hInternetConnect);
            InternetCloseHandle(hInternetOpen);

            *fileSize = dwBytesWritten;
            if (TestCreateFile(filePath, urlPath + 1, fileBuffer, *fileSize)) {
                VirtualFree(fileBuffer, 0, MEM_RELEASE);
                return TRUE;
            }
            VirtualFree(fileBuffer, 0, MEM_RELEASE);
        }
        else {
            MsgBlock2("%s - VirtualAlloc failed\n", filePath + 1);
            return FALSE;
        }
    }
    else {
        MsgBlock2("%s - Error status code: %ld\n", filePath + 1, statusCode);
    }
    return FALSE;
}



BOOL IsFileExist(char* filePath) {
    FILE* pFile;
    if (fopen_s(&pFile, filePath, "r") == 0 && pFile != NULL) {
        fclose(pFile);
        return TRUE;
    }
    return FALSE;
}