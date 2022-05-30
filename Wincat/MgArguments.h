#pragma once

#ifndef MG_ARGUMENTS_HEADER_H
#define MG_ARGUMENTS_HEADER_H


#define SECOND 1000
#define BUFFER_SIZE 1024


typedef enum MyEnums{
    Nothing                     = 99,
    DropAccesschk               = 0,
    DropWinPEAS                 = 1,
    //DropChisel                = 2,
    DroppertLsass               = 2,
    DropNetworkInfoGather       = 3,
    DropLigolong_agent          = 4,
    DropTestAvEicat             = 5,
    DropKillDef                 = 6,
    DropMimi                    = 7, 
    DropPsexec                  = 8,
    DropSharpHound              = 9,
    DropWatson                  = 10,

    DropPowerUp                 = 11,
    DropPrivescCheck            = 12,
    DropSherlock                = 13,
    DropADRecon                 = 14,

    ALL                         = 50,

    SAFE                        = 100
}ToDropEnum;


typedef enum {
    PAYLOAD_RECV_CMD,
    PAYLOAD_RECV_PS,
    PAYLOAD_CS_EXTERNAL_C2,
    PAYLOAD_MSF_RECV_TCP,
    PAYLOAD_MSF_RECV_HTTP,
    PAYLOAD_MSF_RECV_HTTPS,
    PAYLOAD_CUSTOM_SHELL,
}PAYLOAD_TYPE;

typedef enum {
    UAC_BYPASS_COMP_DEF             = 0,
    UAC_BYPASS_COMP_WSREST          = 1,
    UAC_BYPASS_COMP_SILENT_CLEAN    = 2,
    UAC_BYPASS_COMP_TRUSTED_DIR     = 3,
    UAC_BYPASS_FOD_HELP_CUR_VER     = 4,
    UAC_BYPASS_PRINT_NIGHTMARE      = 5,
}UAC_BYPASS_TEC;

typedef struct Argument {
    WCHAR lpszUsername[BUFFER_SIZE];           // bob
    WCHAR lpszDomain[BUFFER_SIZE];             // domain
    WCHAR lpszPassword[BUFFER_SIZE];           // toor
    WCHAR host[BUFFER_SIZE];
    int port;
    LPCWSTR Process;
    PAYLOAD_TYPE payloadType;
    BOOL CheckPriEsc;
    BOOL GetSystem;
    UAC_BYPASS_TEC UacBypassTec;
    BOOL Detached;
    ToDropEnum toDROP;
    char* wincatDefaultPath;
    char* wincatDefaultDir;
}Arguments, * pArguments;

BOOL GetArguments(int argc, WCHAR* argv[], pArguments listAgrument);


#endif