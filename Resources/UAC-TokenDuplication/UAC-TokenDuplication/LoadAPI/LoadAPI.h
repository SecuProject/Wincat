#pragma once

typedef HMODULE(WINAPI *LoadLibraryA_F)(LPCTSTR);

typedef BOOL(WINAPI *TerminateProcess_F)(HANDLE,UINT);


typedef struct {
	TerminateProcess_F TerminateProcessF;
}Kernel32_API;


typedef BOOL(WINAPI *AllocateAndInitializeSid_F)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
typedef BOOL(WINAPI *CheckTokenMembership_F)(HANDLE, PSID, PBOOL);
typedef PVOID(WINAPI *FreeSid_F)(PSID);
typedef BOOL(WINAPI *OpenProcessToken_F)(HANDLE,DWORD,PHANDLE);
typedef BOOL(WINAPI *DuplicateTokenEx_F)(HANDLE,DWORD,LPSECURITY_ATTRIBUTES,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE);
typedef BOOL(WINAPI *ImpersonateLoggedOnUser_F)(HANDLE);
typedef BOOL(WINAPI *CreateProcessWithLogonW_F)(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *CreateWellKnownSid_F)(WELL_KNOWN_SID_TYPE,PSID,PSID,DWORD*);
typedef BOOL(WINAPI *GetTokenInformation_F)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
typedef BOOL(WINAPI *DuplicateToken_F)(HANDLE,SECURITY_IMPERSONATION_LEVEL,PHANDLE);


typedef struct {
	AllocateAndInitializeSid_F AllocateAndInitializeSidF;
	CheckTokenMembership_F CheckTokenMembershipF;
	FreeSid_F FreeSidF;
	OpenProcessToken_F OpenProcessTokenF;
	DuplicateTokenEx_F DuplicateTokenExF;
	ImpersonateLoggedOnUser_F ImpersonateLoggedOnUserF;
	CreateProcessWithLogonW_F CreateProcessWithLogonWF;
	CreateWellKnownSid_F CreateWellKnownSidF;
	GetTokenInformation_F GetTokenInformationF;
	DuplicateToken_F DuplicateTokenF;
}Advapi32_API;


typedef BOOL(WINAPI *ShellExecuteExA_F)(SHELLEXECUTEINFOA *);


typedef struct {
	ShellExecuteExA_F ShellExecuteExAF;
}Shell32_API;


typedef NTSTATUS(WINAPI *NtSetInformationToken_F)(HANDLE,TOKEN_INFORMATION_CLASS,PVOID,ULONG);
typedef NTSTATUS(WINAPI *NtFilterToken_F)(HANDLE,ULONG,PVOID,PVOID,PVOID,HANDLE);


typedef struct {
	NtSetInformationToken_F NtSetInformationTokenF;
	NtFilterToken_F NtFilterTokenF;
}ntdll_API;



typedef struct {
	Kernel32_API Kernel32Api;
	Advapi32_API Advapi32Api;
	Shell32_API Shell32Api;
	ntdll_API ntdllApi;
}API_Call;


#ifdef __cplusplus
extern "C" {
#endif
	BOOL loadApi(API_Call *APICall);
#ifdef __cplusplus
}
#endif
