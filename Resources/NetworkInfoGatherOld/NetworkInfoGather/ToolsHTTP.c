#include <windows.h>
#include <stdio.h>

#include "ToolsHTTP.h"

#pragma warning(disable:4996)

const char* userAgentList[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
    "Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
};
BOOL GetHTTPReturnCode(char* serverResponce, int* serverCode) {
   // int serverResponceSize = strlen(serverResponce);
    const char delim1[] = "HTTP/1.1 ";
    const char delim2[] = " ";
    char* ptr1, * ptr2;
    char buffer[SERVER_VERSION_SIZE];

    ptr1 = strstr(serverResponce, delim1);
    if (ptr1 != NULL) {
        ptr1 = ptr1 + sizeof(delim1) - 1;
        ptr2 = strstr(ptr1, delim2);
        if (ptr2 != NULL) {
            strncpy_s(buffer, SERVER_VERSION_SIZE, ptr1, ptr2 - ptr1);

            *serverCode = atoi(buffer);
            return TRUE;
        }
    }
    *serverCode = 0;
    return FALSE;
}
BOOL GetHTTPserverVersion(char* serverResponce, char* serverVersion, int bannerBufferSize) {
    //int serverResponceSize = strlen(serverResponce);
    const char delim1[] = "Server:";
    const char delim2[] = "\r\n";
    char* ptr1, * ptr2;

    ptr1 = strstr(serverResponce, delim1);
    if (ptr1 != NULL) {
        ptr1 = ptr1 + sizeof(delim1);
        ptr2 = strstr(ptr1, delim2);
        if (ptr2 != NULL) {
            int bufferSize = (ptr2 - ptr1 > bannerBufferSize)? bannerBufferSize - 1 : ptr2 - ptr1;
            //strncpy_s(serverVersion, bufferSize, ptr1, bannerBufferSize );
            strncpy(serverVersion, ptr1, bufferSize);
            return TRUE;
        }
    }
    return FALSE;
}
