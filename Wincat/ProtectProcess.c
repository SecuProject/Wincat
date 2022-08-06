#include <Windows.h>
#include <stdio.h>
#include <sddl.h>
#include <winternl.h>

#include "Message.h"
#include "Tools.h"
#include "LoadAPI.h"

const char cAllowDlls[][MAX_PATH] = {
    "api-ms-win-core-",
    "appresolver.",
    "bcryptprimitives.",
    "comctl32.",
    "imm32.",
    "kernel32",
    "kernelbase",
    "mskeyprotect.",
    "mswsock.",
    "napinsp.",
    "ncryptsslp.",
    "ndfapi.",
    "nlaapi.",
    "nlansp_c.",
    "ntdll.",
    "onecoreuapcommonproxystub.",
    "ondemandconnroutehelper.",
    "pnrpnsp.",
    "propsys.",
    "rpcrt4.",
    "rsaenh.",
    "schannel.",
    "sfc_os.",
    "shell32.",
    "sspicli.",
    "urlmon.",
    "user32.",
    "uxtheme.",
    "windows.staterepositoryps.",
    "windows.storage.",
    "winhttp.",
    "winrnr.",
    "wintypes.",
    "wshbth."
};


NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID* BaseAddress);

typedef void (WINAPI* LdrLoadDll_) (PWSTR SearchPath OPTIONAL,
    PULONG DllCharacteristics OPTIONAL,
    PUNICODE_STRING DllName,
    PVOID* BaseAddress);

LPVOID lpAddr;
CHAR OriginalBytes[50];


#ifdef _WIN64

VOID HookLoadDll64(LPVOID lpAddr) {
    DWORD oldProtect;// , oldOldProtect;
    //void* hLdrLoadDll = &_LdrLoadDll;

    // our trampoline 
    unsigned char patch[] = {
        0x49, 0xbb,
        0xFF, 0xFF, 0xFF, 0xFF,     // Address function (64bit)
        0xFF, 0xFF, 0xFF, 0xFF,     // 
        0x41, 0xff, 0xe3
    };

    // add in the address of our hook
    *(void**)(patch + 2) = &_LdrLoadDll;

    // write the hook
    VirtualProtect(lpAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(lpAddr, patch, sizeof(patch));
    VirtualProtect(lpAddr, sizeof(patch), oldProtect, &oldProtect);

    return;
}
#else
VOID HookLoadDll32(LPVOID lpAddr) {
    DWORD oldProtect;// , oldOldProtect;
    //void* hLdrLoadDll = &_LdrLoadDll;

    // our trampoline 
    unsigned char patch[6] = {
        0x68,
        0xFF,0xFF,0xFF,0xFF, // Address function (32bit)
        0xc3
    };
    *(void**)(patch + 1) = &_LdrLoadDll;

    // write the hook
    VirtualProtect(lpAddr, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(lpAddr, patch, sizeof(patch));
    VirtualProtect(lpAddr, sizeof(patch), oldProtect, &oldProtect);

    return;
}
#endif


NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID* BaseAddress) {
    INT i;
    DWORD dwOldProtect = 0;
    BOOL bAllow = FALSE;
    //DWORD dwbytesWritten;
    CHAR cDllName[MAX_PATH];

    sprintf_s(cDllName, MAX_PATH, "%ws", DllName->Buffer);

    for (i = 0; i < sizeof(cAllowDlls) / MAX_PATH; i++) {
        if (CheckStrMatch(cDllName, cAllowDlls[i])) {
            bAllow = TRUE;

            VirtualProtect(lpAddr, sizeof(OriginalBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
            memcpy(lpAddr, OriginalBytes, sizeof(OriginalBytes));
            VirtualProtect(lpAddr, sizeof(OriginalBytes), dwOldProtect, &dwOldProtect);
            HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
            if (hNtdll == NULL)
                return FALSE;
            LdrLoadDll_ LdrLoadDll = (LdrLoadDll_)GetProcAddress(hNtdll, "LdrLoadDll");
            LdrLoadDll(SearchPath, DllCharacteristics, DllName, BaseAddress);
#ifdef _WIN64
            HookLoadDll64(lpAddr);
#else
            HookLoadDll32(lpAddr);
#endif
        }

    }

    if (!bAllow) {
        printMsg(STATUS_INFO, STATUS_WARNING, "Blocked DLL: %s\n", cDllName);
    }
    return TRUE;
}
BOOL SetHook() {
    HANDLE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL)
        return FALSE;

    lpAddr = (LPVOID)GetProcAddress(hNtdll, "LdrLoadDll");
    if (lpAddr == NULL)
        return FALSE;

    // save the original bytes
    memcpy(OriginalBytes, lpAddr, 50);
#ifdef _WIN64
    HookLoadDll64(lpAddr);
#else
    HookLoadDll32(lpAddr);
#endif
    return TRUE;
}

BOOL ProtectProcessFromUser(VOID) {
	SECURITY_ATTRIBUTES sa;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProcess == NULL) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Could not load the handle");
		return FALSE;
	}
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P", SDDL_REVISION_1, &(sa.lpSecurityDescriptor), NULL)) {
		CloseHandle(hProcess); // TO CHECK !
		return FALSE;
	}
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;
	SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor);
	CloseHandle(hProcess); // TO CHECK !
	return TRUE;
}

BOOL EnableACG(VOID) {
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SigPolicy;
	ZeroMemory(&SigPolicy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
	SigPolicy.MicrosoftSignedOnly = TRUE;
	return SetProcessMitigationPolicy(ProcessSignaturePolicy, &SigPolicy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
}



BOOL CheckForDebugger(VOID) {
    typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
        _In_      HANDLE           ProcessHandle,
        _In_      UINT             ProcessInformationClass,
        _Out_     PVOID            ProcessInformation,
        _In_      ULONG            ProcessInformationLength,
        _Out_opt_ PULONG           ReturnLength
        );
    const UINT ProcessDebugPort = 7;

    pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
    DWORD isDebuggerPresent = 0;
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));

    if (NULL != hNtDll) {
        NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NULL != NtQueryInformationProcess) {
            NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &isDebuggerPresent, sizeof(DWORD), NULL);
            return status == 0x0 && isDebuggerPresent != 0;
        }
    }
    return FALSE;
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

BOOL CheckCodeSection(VOID) {
    DWORD buffSize = BUFFER_SIZE;
    char* processName = (char*)malloc(BUFFER_SIZE);

    if (processName != NULL) {
        HANDLE processHandle = GetCurrentProcess();

        if (processHandle != NULL) {
            if (QueryFullProcessImageNameA(processHandle, 0, processName, &buffSize)) {
                HMODULE hImagehlp = LoadLibraryA("Imagehlp.dll");

                if (NULL != hImagehlp) {
                    typedef DWORD(NTAPI* pfnMapFileAndCheckSumA)(PCSTR Filename, PDWORD HeaderSum, PDWORD CheckSum);
                    pfnMapFileAndCheckSumA MapFileAndCheckSumA = (pfnMapFileAndCheckSumA)GetProcAddress(hImagehlp, "MapFileAndCheckSumA");
                    if (MapFileAndCheckSumA != NULL) {
                        DWORD HeaderCheckSum = 0;
                        DWORD CheckSum = 0;

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

BOOL ProtectProcess(VOID) {
    if (CheckForDebugger()) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Debugger detected");
#if _DEBUG
        return FALSE;
#else
        exit(0);
#endif
    } else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Check For Debugger[1]: OK\n");



	if (!ProtectProcessFromUser()) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to protect process");
        return FALSE;
	}else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Process protected\n");



    if (IsDebuggerPresentPEB()) {
        printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Debugger detected");
#if _DEBUG
        return FALSE;
#else
        exit(0);
#endif
    } else
        printMsg(STATUS_INFO, LEVEL_VERBOSE, "Check For Debugger[2]: OK\n");
    return TRUE;
}