#pragma once

////// Start static header
//
#include <TlHelp32.h>
#include <shellapi.h>
#include <wininet.h>
#include <compressapi.h>

//
////// Stop static header

typedef HMODULE(WINAPI *LoadLibraryA_F)(LPCSTR);

typedef HANDLE(WINAPI *CreateToolhelp32Snapshot_F)(DWORD,DWORD);
typedef BOOL(WINAPI *Process32First_F)(HANDLE,LPPROCESSENTRY32);
typedef BOOL(WINAPI *Process32Next_F)(HANDLE,LPPROCESSENTRY32);
typedef BOOL(WINAPI *Process32FirstW_F)(HANDLE,LPPROCESSENTRY32W);
typedef BOOL(WINAPI *Process32NextW_F)(HANDLE,LPPROCESSENTRY32W);
typedef BOOL(WINAPI *CloseHandle_F)(HANDLE);
typedef DWORD(WINAPI *GetModuleFileNameW_F)(HMODULE,LPWSTR,DWORD);
typedef HANDLE(WINAPI *GetCurrentProcess_F)();
typedef HANDLE(WINAPI *OpenProcess_F)(DWORD,BOOL,DWORD);
typedef BOOL(WINAPI *Wow64DisableWow64FsRedirection_F)(PVOID);
typedef BOOL(WINAPI *Wow64RevertWow64FsRedirection_F)(PVOID);
typedef HANDLE(WINAPI *CreateFileA_F)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL(WINAPI *DeleteFileA_F)(LPCSTR);
typedef BOOL(WINAPI *VirtualProtect_F)(LPVOID,SIZE_T,DWORD,PDWORD);
typedef BOOL(WINAPI *VirtualFree_F)(LPVOID,SIZE_T,DWORD);
typedef LPVOID(WINAPI *VirtualAlloc_F)(LPVOID,SIZE_T,DWORD,DWORD);
typedef BOOL(WINAPI *CreateDirectoryA_F)(LPCSTR,LPSECURITY_ATTRIBUTES);
typedef BOOL(WINAPI *CopyFileA_F)(LPCSTR,LPCSTR,BOOL);
typedef DWORD(WINAPI *GetModuleFileNameA_F)(HMODULE,LPSTR,DWORD);
typedef DWORD(WINAPI *GetProcessId_F)(HANDLE);
typedef BOOL(WINAPI *CreateProcessW_F)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef UINT(WINAPI *GetWindowsDirectoryA_F)(LPSTR,UINT);
typedef HLOCAL(WINAPI *LocalAlloc_F)(UINT,SIZE_T);
typedef HLOCAL(WINAPI *LocalFree_F)(HLOCAL);
typedef BOOL(WINAPI *CreateDirectoryW_F)(LPCWSTR,LPSECURITY_ATTRIBUTES);
typedef BOOL(WINAPI *SetFileInformationByHandle_F)(HANDLE,FILE_INFO_BY_HANDLE_CLASS,LPVOID,DWORD);
typedef HANDLE(WINAPI *CreateFileW_F)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL(WINAPI *WriteFile_F)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);


typedef struct {
	CreateToolhelp32Snapshot_F CreateToolhelp32SnapshotF;
	Process32First_F Process32FirstF;
	Process32Next_F Process32NextF;
	Process32FirstW_F Process32FirstWF;
	Process32NextW_F Process32NextWF;
	CloseHandle_F CloseHandleF;
	GetModuleFileNameW_F GetModuleFileNameWF;
	GetCurrentProcess_F GetCurrentProcessF;
	OpenProcess_F OpenProcessF;
	Wow64DisableWow64FsRedirection_F Wow64DisableWow64FsRedirectionF;
	Wow64RevertWow64FsRedirection_F Wow64RevertWow64FsRedirectionF;
	CreateFileA_F CreateFileAF;
	DeleteFileA_F DeleteFileAF;
	VirtualProtect_F VirtualProtectF;
	VirtualFree_F VirtualFreeF;
	VirtualAlloc_F VirtualAllocF;
	CreateDirectoryA_F CreateDirectoryAF;
	CopyFileA_F CopyFileAF;
	GetModuleFileNameA_F GetModuleFileNameAF;
	GetProcessId_F GetProcessIdF;
	CreateProcessW_F CreateProcessWF;
	GetWindowsDirectoryA_F GetWindowsDirectoryAF;
	LocalAlloc_F LocalAllocF;
	LocalFree_F LocalFreeF;
	CreateDirectoryW_F CreateDirectoryWF;
	SetFileInformationByHandle_F SetFileInformationByHandleF;
	CreateFileW_F CreateFileWF;
	WriteFile_F WriteFileF;
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
typedef BOOL(WINAPI *CreateProcessWithTokenW_F)(HANDLE,DWORD,LPCWSTR,LPWSTR,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *LookupPrivilegeValueA_F)(LPCSTR,LPCSTR,PLUID);
typedef BOOL(WINAPI *LookupPrivilegeValueW_F)(LPCWSTR,LPCWSTR,PLUID);
typedef BOOL(WINAPI *AdjustTokenPrivileges_F)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
typedef BOOL(WINAPI *SetTokenInformation_F)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD);
typedef PDWORD(WINAPI *GetSidSubAuthority_F)(PSID,DWORD);
typedef DWORD(WINAPI *GetLengthSid_F)(PSID);
typedef BOOL(WINAPI *PrivilegeCheck_F)(HANDLE,PPRIVILEGE_SET,LPBOOL);
typedef LSTATUS(WINAPI *RegOpenKeyExA_F)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
typedef LSTATUS(WINAPI *RegQueryValueExA_F)(HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);
typedef LSTATUS(WINAPI *RegCloseKey_F)(HKEY);
typedef LSTATUS(WINAPI *RegCreateKeyExA_F)(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,CONST LPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
typedef LSTATUS(WINAPI *RegDeleteKeyA_F)(HKEY,LPCSTR);
typedef LSTATUS(WINAPI *RegSetValueExA_F)(HKEY,LPCSTR,DWORD,DWORD,CONST BYTE *,DWORD);
typedef LSTATUS(WINAPI *RegEnumKeyExA_F)(HKEY,DWORD,LPSTR,LPDWORD,LPDWORD,LPSTR,LPDWORD,PFILETIME);
typedef BOOL(WINAPI *LookupAccountSidA_F)(LPCSTR,PSID,LPSTR,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE);
typedef BOOL(WINAPI *ConvertSidToStringSidA_F)(PSID,LPSTR *);
typedef SC_HANDLE(WINAPI *OpenSCManagerA_F)(LPCSTR,LPCSTR,DWORD);
typedef SC_HANDLE(WINAPI *OpenServiceA_F)(SC_HANDLE,LPCSTR,DWORD);
typedef BOOL(WINAPI *CloseServiceHandle_F)(SC_HANDLE);
typedef BOOL(WINAPI *QueryServiceConfigA_F)(SC_HANDLE,LPQUERY_SERVICE_CONFIGA,DWORD,LPDWORD);
typedef BOOL(WINAPI *StartServiceA_F)(SC_HANDLE,DWORD,LPCSTR);
typedef BOOL(WINAPI *QueryServiceStatusEx_F)(SC_HANDLE,SC_STATUS_TYPE,LPBYTE,DWORD,LPDWORD);
typedef BOOL(WINAPI *LogonUserW_F)(LPCWSTR,LPCWSTR,LPCWSTR,DWORD,DWORD,PHANDLE);


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
	CreateProcessWithTokenW_F CreateProcessWithTokenWF;
	LookupPrivilegeValueA_F LookupPrivilegeValueAF;
	LookupPrivilegeValueW_F LookupPrivilegeValueWF;
	AdjustTokenPrivileges_F AdjustTokenPrivilegesF;
	SetTokenInformation_F SetTokenInformationF;
	GetSidSubAuthority_F GetSidSubAuthorityF;
	GetLengthSid_F GetLengthSidF;
	PrivilegeCheck_F PrivilegeCheckF;
	RegOpenKeyExA_F RegOpenKeyExAF;
	RegQueryValueExA_F RegQueryValueExAF;
	RegCloseKey_F RegCloseKeyF;
	RegCreateKeyExA_F RegCreateKeyExAF;
	RegDeleteKeyA_F RegDeleteKeyAF;
	RegSetValueExA_F RegSetValueExAF;
	RegEnumKeyExA_F RegEnumKeyExAF;
	LookupAccountSidA_F LookupAccountSidAF;
	ConvertSidToStringSidA_F ConvertSidToStringSidAF;
	OpenSCManagerA_F OpenSCManagerAF;
	OpenServiceA_F OpenServiceAF;
	CloseServiceHandle_F CloseServiceHandleF;
	QueryServiceConfigA_F QueryServiceConfigAF;
	StartServiceA_F StartServiceAF;
	QueryServiceStatusEx_F QueryServiceStatusExF;
	LogonUserW_F LogonUserWF;
}Advapi32_API;


typedef BOOL(WINAPI *ShellExecuteExA_F)(SHELLEXECUTEINFOA *);
typedef HINSTANCE(WINAPI *ShellExecuteA_F)(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);


typedef struct {
	ShellExecuteExA_F ShellExecuteExAF;
	ShellExecuteA_F ShellExecuteAF;
}Shell32_API;


typedef INT(WINAPI *connect_F)(SOCKET,CONST struct sockaddr*,INT);
typedef unsigned long(WINAPI *inet_addr_F)(CONST CHAR *);
typedef INT(WINAPI *recv_F)(SOCKET,CHAR *,INT,INT);
typedef INT(WINAPI *closesocket_F)(SOCKET);
typedef SOCKET(WINAPI *socket_F)(INT,INT,INT);
typedef INT(WINAPI *WSAGetLastError_F)();


typedef struct {
	connect_F connectF;
	inet_addr_F inet_addrF;
	recv_F recvF;
	closesocket_F closesocketF;
	socket_F socketF;
	WSAGetLastError_F WSAGetLastErrorF;
}Ws2_32_API;


typedef HINTERNET(WINAPI *HttpOpenRequestA_F)(HINTERNET,LPCSTR,LPCSTR,LPCSTR,LPCSTR,LPCSTR,DWORD,DWORD_PTR);
typedef BOOL(WINAPI *InternetSetOptionA_F)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL(WINAPI *InternetReadFile_F)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef HINTERNET(WINAPI *InternetOpenA_F)(LPCSTR,DWORD,LPCSTR,LPCSTR,DWORD);
typedef BOOL(WINAPI *InternetCloseHandle_F)(HINTERNET);
typedef HINTERNET(WINAPI *InternetConnectW_F)(HINTERNET,LPCWSTR,INTERNET_PORT,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD_PTR);
typedef BOOL(WINAPI *HttpSendRequestA_F)(HINTERNET,LPCSTR,DWORD,LPVOID,DWORD);


typedef struct {
	HttpOpenRequestA_F HttpOpenRequestAF;
	InternetSetOptionA_F InternetSetOptionAF;
	InternetReadFile_F InternetReadFileF;
	InternetOpenA_F InternetOpenAF;
	InternetCloseHandle_F InternetCloseHandleF;
	InternetConnectW_F InternetConnectWF;
	HttpSendRequestA_F HttpSendRequestAF;
}Wininet_API;


typedef BOOL(WINAPI *CreateDecompressor_F)(DWORD,PCOMPRESS_ALLOCATION_ROUTINES,PDECOMPRESSOR_HANDLE);
typedef BOOL(WINAPI *Decompress_F)(DECOMPRESSOR_HANDLE,LPCVOID,SIZE_T,PVOID,SIZE_T,PSIZE_T);
typedef BOOL(WINAPI *CloseDecompressor_F)(DECOMPRESSOR_HANDLE);


typedef struct {
	CreateDecompressor_F CreateDecompressorF;
	Decompress_F DecompressF;
	CloseDecompressor_F CloseDecompressorF;
}Cabinet_API;


typedef NTSTATUS(WINAPI *NtQueryInformationProcess_F)(HANDLE, UINT, PVOID, ULONG, PULONG);


typedef struct {
	NtQueryInformationProcess_F NtQueryInformationProcessF;
}ntdll_API;


typedef BOOL(WINAPI *CreateEnvironmentBlock_F)(LPVOID*,HANDLE,BOOL);
typedef BOOL(WINAPI *GetUserProfileDirectoryW_F)(HANDLE,LPWSTR,LPDWORD);
typedef BOOL(WINAPI *DestroyEnvironmentBlock_F)(LPVOID);


typedef struct {
	CreateEnvironmentBlock_F CreateEnvironmentBlockF;
	GetUserProfileDirectoryW_F GetUserProfileDirectoryWF;
	DestroyEnvironmentBlock_F DestroyEnvironmentBlockF;
}Userenv_API;



typedef struct {
	Kernel32_API Kernel32Api;
	Advapi32_API Advapi32Api;
	Shell32_API Shell32Api;
	Ws2_32_API Ws2_32Api;
	Wininet_API WininetApi;
	Cabinet_API CabinetApi;
	ntdll_API ntdllApi;
	Userenv_API UserenvApi;
}API_Call;


BOOL loadApi(API_Call *APICall);
