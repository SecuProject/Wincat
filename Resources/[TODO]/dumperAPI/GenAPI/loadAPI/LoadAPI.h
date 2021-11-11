#pragma once

////// Start static header
//

#include <DbgHelp.h>
#include <TlHelp32.h>


//
////// Stop static header

typedef HMODULE(WINAPI *LoadLibraryA_F)(LPCTSTR);

typedef BOOL(WINAPI *CloseHandle_F)(HANDLE);
typedef HANDLE(WINAPI *CreateFileA_F)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE(WINAPI *GetCurrentProcess_F)();
typedef HANDLE(WINAPI *CreateToolhelp32Snapshot_F)(DWORD,DWORD);
typedef HANDLE(WINAPI *OpenProcess_F)(DWORD,BOOL,DWORD);
typedef BOOL(WINAPI *Process32First_F)(HANDLE,LPPROCESSENTRY32 );
typedef BOOL(WINAPI *Process32Next_F)(HANDLE,LPPROCESSENTRY32);


typedef struct {
	CloseHandle_F CloseHandleF;
	CreateFileA_F CreateFileAF;
	GetCurrentProcess_F GetCurrentProcessF;
	CreateToolhelp32Snapshot_F CreateToolhelp32SnapshotF;
	OpenProcess_F OpenProcessF;
	Process32First_F Process32FirstF;
	Process32Next_F Process32NextF;
}Kernel32_API;


typedef BOOL(WINAPI *LookupPrivilegeValueA_F)(LPCSTR,LPCSTR,PLUID);
typedef BOOL(WINAPI *OpenProcessToken_F)(HANDLE,DWORD,PHANDLE);
typedef BOOL(WINAPI *AdjustTokenPrivileges_F)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD);
typedef BOOL(WINAPI *PrivilegeCheck_F)(HANDLE,PPRIVILEGE_SET,LPBOOL);


typedef struct {
	LookupPrivilegeValueA_F LookupPrivilegeValueAF;
	OpenProcessToken_F OpenProcessTokenF;
	AdjustTokenPrivileges_F AdjustTokenPrivilegesF;
	PrivilegeCheck_F PrivilegeCheckF;
}Advapi32_API;


typedef BOOL(WINAPI *MiniDumpWriteDump_F)(HANDLE,DWORD,HANDLE,MINIDUMP_TYPE,PMINIDUMP_EXCEPTION_INFORMATION,PMINIDUMP_USER_STREAM_INFORMATION,PMINIDUMP_CALLBACK_INFORMATION);


typedef struct {
	MiniDumpWriteDump_F MiniDumpWriteDumpF;
}Dbghelp_API;



typedef struct {
	Kernel32_API Kernel32Api;
	Advapi32_API Advapi32Api;
	Dbghelp_API DbghelpApi;
}API_Call;


#ifdef __cplusplus
extern "C" {
#endif
	BOOL loadApi(API_Call *APICall);
#ifdef __cplusplus
}
#endif
