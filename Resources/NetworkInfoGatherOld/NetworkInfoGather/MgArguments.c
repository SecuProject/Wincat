#include <windows.h>
#include <stdio.h>
#include "MgArguments.h"

#define MAX_IP_ADDR_SIZE 15
#define MIN_IP_ADDR_SIZE 7


VOID PrintMenu(){
    printf("\nNetwork scanner.\n\n");

    printf("NetworkInfoGather.exe -l\n");
    printf("NetworkInfoGather.exe [-i INTERFACE_NB] [-s icmp|arp|passif|passifT]|[-t IP_ADDRESS] [-A] [-ps] [-o FILEPATH] \n\n");

    printf("Select option:\n");
    printf("\t-h\t\tPrint help menu\n");
    printf("\t-l\t\tList interfaces\n");
    printf("\t-i INTERFACE_NB Select the interface\n");
    printf("\t-ps\t\tEnable port scan\n");
    printf("\t-b\t\tEnable brute force enable\n");
    printf("\t-A\t\tAgressif scan (grab banner and brute force enable)\n");
    printf("\t-o FILEPATH\tOutput into a file\n");
    printf("\t-t IP_ADDRESS\tTarget ip Address or range. Allowed formats:\n");
    printf("\t\t\t\te.g. '192.168.1.1' or '192.168.1.1-5'\n");
    
   
    printf("Select scan:\n");
    printf("\t-s icmp\t\tSelect icmp scan.\n");
    printf("\t-s arp\t\tSelect arp scan [DEFAULT].\n");
    printf("\t-s passif\tSelect passif mode (Require Administrator privilege).\n");
    printf("\t-s passifT\tSelect passif mode (Will grab the list of host from the arp table of the system).\n\n");
}
BOOL GetArguments(int argc, char* argv[], pArguments listAgrument) {
    listAgrument->isListInterface = FALSE;
    listAgrument->interfaceNb = 0;
    listAgrument->typeOfScan = ARP_Scan;
    listAgrument->advancedScan = FALSE;
    listAgrument->portScan = FALSE;
    listAgrument->bruteforce = FALSE;
    listAgrument->ouputFile = NULL;
    listAgrument->ipAddress = NULL;

    if (argc == 1) {
        PrintMenu();
        return FALSE;
    }else if (argc == 2 && (strcmp(argv[1], "-l") == 0)) {
        listAgrument->isListInterface = TRUE;
        return TRUE;
    } else {
        for (int count = 0; count < argc; count++) {
            if ((argv[count][0] == '-' || argv[count][0] == '/') && strlen(argv[count]) > 1) {
                if (argv[count][1] == 's' && argc >= count + 1) {
                    if ((strcmp(argv[count + 1], "icmp") == 0))
                        listAgrument->typeOfScan = ICMP_Scan;
                    else if (strcmp(argv[count + 1], "arp") == 0) 
                        listAgrument->typeOfScan = ARP_Scan;
                    else if (strcmp(argv[count + 1], "passif") == 0) 
                        listAgrument->typeOfScan = Passif_Packet_Sniffing;
                    else if (strcmp(argv[count + 1], "passifT") == 0) 
                        listAgrument->typeOfScan = Passif_Scan;
                    count++;
                } else if (argc >= count + 1 && argv[count][1] == L'o') {
                    if (fopen_s(&listAgrument->ouputFile, argv[count + 1], "a") != 0)
                        return FALSE;
                    listAgrument->ouputFile = listAgrument->ouputFile;
                    count++;
                } else if (argc >= count + 1 && argv[count][1] == L't') {
                    size_t strSize = strlen(argv[count + 1]);
                    listAgrument->ipAddress = (char*)calloc(strSize + 1, 1);
                    if (listAgrument->ipAddress == NULL)
                        return FALSE;
                    strcpy_s(listAgrument->ipAddress, strSize + 1, argv[count + 1]);
                    count++;
                } else if (argv[count][1] == L'A') {
                    listAgrument->portScan = TRUE;
                    listAgrument->advancedScan = TRUE;
                    listAgrument->bruteforce = TRUE;
                } else if (argv[count][1] == L'b') {
                    listAgrument->bruteforce = TRUE;
                } else if (strlen(argv[count]) == 3 && argv[count][1] == L'p' && argv[count][2] == L's') {
                    listAgrument->portScan = TRUE;
                } else if (argc >= count + 1 && argv[count][1] == L'i') {
                    listAgrument->interfaceNb = atoi(argv[count + 1]);
                    count++;
                } else if ((argv[count][1] == L'h' || argv[count][1] == L'?' || strcmp(argv[count], "--help") == 0) && argc >= count) {
                    PrintMenu();
                    return FALSE;
                } else
                    printf("[!] Unknown argument %s\n", argv[count]);
            }
        }
    }
    return TRUE;


    /*int checkTypeCShell = 0;

    listAgrument->Process = ProcessCmd;
    listAgrument->lpszUsername[0] = 0x00;
    listAgrument->lpszPassword[0] = 0x00;
    listAgrument->lpszDomain[0] = 0x00;
    listAgrument->payloadType = PAYLOAD_RECV_CMD;
    listAgrument->Detached = FALSE;
    listAgrument->GetSystem = FALSE;
    listAgrument->toDROP = Nothing;

    if (argc == 2) {
        if (lstrcmpW(argv[1], L"winpeas") == 0)
            listAgrument->toDROP = DropWinPEAS;
        else if (lstrcmpW(argv[1], L"chisel") == 0)
            listAgrument->toDROP = DropChisel;
        else if (lstrcmpW(argv[1], L"shound") == 0) 
            listAgrument->toDROP = DropSharpHound;
        else if (lstrcmpW(argv[1], L"lsass") == 0) 
            listAgrument->toDROP = DroppertLsass;
        else if (lstrcmpW(argv[1], L"all") == 0) 
            listAgrument->toDROP = ALL;
        else {
            PrintMenu();
            return FALSE;
        }
        return TRUE;
    }
    if (argc < 3) {
        PrintMenu();
        return FALSE;
    }
    lstrcpyW(listAgrument->host, argv[1]);
    listAgrument->port = _wtoi(argv[2]);

    if (!IsIpAddressValid(listAgrument->host)) {
        printOut(pFile,"[x] Invalid ip address '%ws' !\n", argv[1]);
        return FALSE;
    }
    if (!IsPortValid(listAgrument->port)) {
        printOut(pFile,"[x] Invalid port '%ws' (Range: 0-65353) !\n", argv[2]);
        return FALSE;
    }

    for (int count = 3; count < argc; count++) {
        if ((argv[count][0] == L'-' ||   argv[count][0] == L'/') && lstrlen(argv[count]) > 1) {
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
                }
                count++;
            }else if ((argv[count][1] == L'h'|| argv[count][1] == L'?' || lstrcmpW(argv[count], L"--help") == 0) && argc >= count) {
                PrintMenu();
                return FALSE;
            }else
                printOut(pFile,"[!] Unknown argument %ws\n", argv[count]);
        }else {
            if (lstrcmpW(argv[count], L"getsystem") == 0) {
                listAgrument->GetSystem = TRUE;
            } else if (lstrcmpW(argv[count], L"detached") == 0) {
                listAgrument->Detached = TRUE;

            }else if (lstrcmpW(argv[count], L"winpeas") == 0) {
                listAgrument->toDROP = DropWinPEAS;
            }else if (lstrcmpW(argv[count], L"chisel") == 0) {
                listAgrument->toDROP = DropChisel;
            } else if (lstrcmpW(argv[count], L"lsass") == 0) {
                listAgrument->toDROP = DroppertLsass;
            } else if (lstrcmpW(argv[count], L"shound") == 0) {
                listAgrument->toDROP = DropSharpHound;
            }else if (lstrcmpW(argv[count], L"all") == 0) {
                listAgrument->toDROP = ALL;
            }else 
                printOut(pFile,"[!] Unknown argument %ws\n", argv[count]);
        }
    }
    if (checkTypeCShell > 1) {
        PrintMenu();
        return FALSE;
    }*/
    return TRUE;
}