#include <stdio.h>
#include <windows.h>

#include "Message.h"

#if !_DEBUG
MSG_LEVEL msgLevelGlobal = LEVEL_DEFAULT;
#else
MSG_LEVEL msgLevelGlobal = LEVEL_VERBOSE;
#endif



DWORD DisplayError(LPWSTR pszAPI) {
    DWORD lastError = GetLastError();
    LPVOID lpvMessageBuffer;

    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpvMessageBuffer, 0, NULL);

    if (lpvMessageBuffer != NULL) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR (%lu): API:%ws - %ws", lastError, pszAPI, (LPWSTR)lpvMessageBuffer);
        LocalFree(lpvMessageBuffer);
    }
    return lastError;
}

DWORD DisplayErrorMsgSuffix(BOOL isTab, BOOL isVerbose) {
    DWORD lastError = GetLastError();
    printf(" (%lu) !\n", lastError);

    if (isVerbose && lastError != 0) {
        LPVOID lpvMessageBuffer;

        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&lpvMessageBuffer, 0, NULL);

        if (lpvMessageBuffer != NULL) {
            if(isTab)
                printMsg(STATUS_INFO2, LEVEL_VERBOSE, "%ws\n", (LPWSTR)lpvMessageBuffer);
            else
                printMsg(STATUS_INFO, LEVEL_VERBOSE, "%ws\n", (LPWSTR)lpvMessageBuffer);
            LocalFree(lpvMessageBuffer);
        }
    }
    return lastError;
}

void printMsgPrefix(MSG_STATUS msgStatus) {
    switch (msgStatus) {

    case STATUS_OK2:
        printf("\t");
    case STATUS_OK:
        printf("[+] ");
        break;

    case STATUS_ERROR2:
        printf("\t");
    case STATUS_ERROR:
        printf("[x] ");
        break;

    case STATUS_WARNING2:
        printf("\t");
    case STATUS_WARNING:
        printf("[!] "); // [w]
        break;

    case STATUS_TITLE2:
        printf("\t");
    case STATUS_TITLE:
        printf("[-] ");
        break;

    case STATUS_DEBUG:
        printf("[D] ");
        break;

    case STATUS_INFO2:
        printf("\t");
    case STATUS_INFO:
        printf("[i] ");
        break;

    case STATUS_NONE:
    default:
        break;
    }
}
void printMsgSuffix(MSG_STATUS msgStatus) {
    switch (msgStatus) {
    case STATUS_ERROR2:
        DisplayErrorMsgSuffix(TRUE,msgLevelGlobal > LEVEL_DEFAULT);
        break;
    case STATUS_ERROR:
        DisplayErrorMsgSuffix(FALSE,msgLevelGlobal > LEVEL_DEFAULT);
        break;
    case STATUS_NONE:
    default:
        break;
    }
}

void printMsg(MSG_STATUS msgStatus, MSG_LEVEL msgLevel, const char* format, ...) {
    if (msgLevel <= msgLevelGlobal) {
        printMsgPrefix(msgStatus);

        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);

        printMsgSuffix(msgStatus);
    }
}