#include <windows.h>
#include <stdio.h>
#include <winternl.h>


BOOL ErasePEHeaderFromMemory() {
    printf("[-] Erasing PE header from memory\n");
    DWORD OldProtect = 0;


    // Get base address of module
    char* pBaseAddr = (char*)GetModuleHandle(NULL);
    if (pBaseAddr != NULL) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        printf("[i] 0x%x\n", si.dwPageSize);

        if (VirtualProtect(pBaseAddr, si.dwPageSize, PAGE_READWRITE, &OldProtect)) {
            RtlSecureZeroMemory(pBaseAddr, si.dwPageSize);  // Erase the header
            //VirtualProtect(pBaseAddr, si.dwPageSize, OldProtect, &OldProtect); 
            VirtualProtect(pBaseAddr, si.dwPageSize, OldProtect| PAGE_GUARD, &OldProtect); // PAGE_GUARD
            return TRUE;
        }
    }
    return FALSE;
}

VOID SizeOfImage() {
    //PULONG newSizeOfImage = 0xffffffffffffffff;
    ULONG newSizeOfImage = 0x100000;


#if _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    // For verbos mode 
    printf("[i] Increasing SizeOfImage in PE Header to: 0x%x\n", newSizeOfImage);

    // The following pointer hackery is because winternl.h defines incomplete PEB types
    PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY)pPeb->Ldr->Reserved2[1]; // pPeb->Ldr->InLoadOrderModuleList
    PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0] /*InLoadOrderLinks*/);
    PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
    *pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + newSizeOfImage);
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
    NTSTATUS status;
    DWORD isDebuggerPresent = 0;
    HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));

    if (NULL != hNtDll) {
        NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        if (NULL != NtQueryInformationProcess) {
            status = NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &isDebuggerPresent, sizeof(DWORD), NULL);
            return status == 0x0 && isDebuggerPresent != 0;
        }
    }
    return FALSE;
}
BOOL IsDebuggerPresentPEB(VOID){
#if _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb->BeingDebugged;
}


int main() {
    /*if (CheckForDebugger()) {
    * printf("[x] Stop debugging program !\n");
        system("pause");
        exit(-1);
    }*/
    
    if (IsDebuggerPresentPEB()) {
        printf("[x] Stop debugging program !\n");
        system("pause");
        exit(-1);
    }

    

    if (!ErasePEHeaderFromMemory()) {
        printf("[!] Fail to Erase PE Header (Anti-dump) !\n");
    }
    SizeOfImage();  // OK with process Hacker
    system("pause");
    return FALSE;
}