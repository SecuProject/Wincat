#include <Windows.h>
#include <stdio.h>
#include <sddl.h>
#include <winternl.h>

#include "Message.h"
#include "Tools.h"
#include "LoadAPI.h"


/*
ConvertStringSecurityDescriptorToSecurityDescriptorA
SetKernelObjectSecurity
*/
BOOL ProtectProcessFromUser(Kernel32_API Kernel32Api) {
    SECURITY_ATTRIBUTES sa;

    if (ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P", SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL)) {
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = FALSE;
        HANDLE hProcess = Kernel32Api.GetCurrentProcessF();
        if (hProcess != NULL) {
            return (SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor));
        } else
            printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Could not load the Current Process handle");

    } else
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Could not Convert String Security Descriptor To Security Descriptor");
    return FALSE;
}

/*
SetProcessMitigationPolicy
*/
BOOL EnableACG(VOID) {
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SigPolicy;
	ZeroMemory(&SigPolicy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
	SigPolicy.MicrosoftSignedOnly = TRUE;
	return SetProcessMitigationPolicy(ProcessSignaturePolicy, &SigPolicy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
}



BOOL CheckForDebugger(Kernel32_API kernel32,ntdll_API ntdllApi) {
    DWORD isDebuggerPresent = 0;
    NTSTATUS status = ntdllApi.NtQueryInformationProcessF(kernel32.GetCurrentProcessF(), ProcessDebugPort, &isDebuggerPresent, sizeof(DWORD), NULL);
    return status == 0x0 && isDebuggerPresent != 0;
}

BOOL IsDebuggerPresentPEB(VOID) {
#if _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb->BeingDebugged;
}


#define BUFFER_SIZE 1024

#define CHECKSUM_SUCCESS            0
#define CHECKSUM_OPEN_FAILURE       1
#define CHECKSUM_MAP_FAILURE        2
#define CHECKSUM_MAPVIEW_FAILURE    3
#define CHECKSUM_UNICODE_FAILURE    4

/*
MapFileAndCheckSumA
QueryFullProcessImageNameA
*/
BOOL CheckCodeSection(Kernel32_API Kernel32Api) {
    DWORD buffSize = BUFFER_SIZE;
    char* processName = (char*)malloc(BUFFER_SIZE);

    if (IsDebuggerPresentPEB()) {
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Debugger detected !\n");
#if !_DEBUG
        exit(0);
#endif
    }

    if (processName != NULL) {
        HANDLE processHandle = Kernel32Api.GetCurrentProcessF();

        if (processHandle != NULL) {
            if (QueryFullProcessImageNameA(processHandle, 0, processName, &buffSize)) {
                HMODULE hImagehlp = LoadLibraryA("Imagehlp.dll");

                if (NULL != hImagehlp) {
                    typedef DWORD(NTAPI* pfnMapFileAndCheckSumA)(PCSTR Filename, PDWORD HeaderSum, PDWORD CheckSum);
                    pfnMapFileAndCheckSumA MapFileAndCheckSumA = (pfnMapFileAndCheckSumA)GetProcAddress(hImagehlp, "MapFileAndCheckSumA");
                    if (MapFileAndCheckSumA != NULL) {
                        DWORD HeaderCheckSum = 0;
                        DWORD CheckSum = 0;

                        if (IsDebuggerPresentPEB()) {
                            printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Debugger detected !\n");
#if !_DEBUG
                            exit(0);
#endif
                        }

                        printMsg(STATUS_TITLE, LEVEL_VERBOSE, "MapFileAndCheckSum:\n");
                        if (MapFileAndCheckSumA(processName, &HeaderCheckSum, &CheckSum) == CHECKSUM_SUCCESS) {
                            printMsg(STATUS_INFO, LEVEL_VERBOSE, "\tHeaderCheckSum: 0x%x\n", HeaderCheckSum);
                            printMsg(STATUS_INFO, LEVEL_VERBOSE, "\tCheckSum: 0x%x\n", CheckSum);
                            free(processName);
                            CloseHandle(processHandle);
                            return HeaderCheckSum == CheckSum;
                        }else
                            printMsg(STATUS_WARNING, LEVEL_DEFAULT, "CheckSum doesn't match !\n");
                    }else
                        printMsg(STATUS_ERROR, LEVEL_VERBOSE, "MapFileAndCheckSumA == NULL");
                }else
                    printMsg(STATUS_ERROR, LEVEL_VERBOSE, "LoadLibraryA == NULL");
            }else
                printMsg(STATUS_ERROR, LEVEL_VERBOSE, "QueryFullProcessImageNameA");
            CloseHandle(processHandle);
}
        free(processName);
    }
    return FALSE;
}

BOOL ProtectProcess(Kernel32_API kernel32, ntdll_API ntdllApi) {
    if (CheckForDebugger(kernel32, ntdllApi)) {
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Debugger detected !\n");
#if _DEBUG
        return FALSE;
#else
        exit(0);
#endif
    } else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Check For Debugger[1]: OK\n");



	if (!ProtectProcessFromUser(kernel32)) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to protect process");
        return FALSE;
	}else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Process protected\n");



    if (IsDebuggerPresentPEB()) {
        printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Debugger detected !\n");
#if _DEBUG
        return FALSE;
#else
        exit(0);
#endif
    } else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Check For Debugger[2]: OK\n");

    if (!CheckCodeSection(kernel32))
        exit(0);
    return TRUE;
}