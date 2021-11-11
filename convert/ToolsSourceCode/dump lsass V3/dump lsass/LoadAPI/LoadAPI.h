#pragma once
#include <tlhelp32.h>
#include <DbgHelp.h>

typedef HMODULE(WINAPI *LoadLibraryA_F)(LPCTSTR);

typedef HANDLE(WINAPI *OpenProcess_F)(DWORD,BOOL,DWORD);
typedef BOOL(WINAPI *CloseHandle_F)(HANDLE);
typedef DWORD(WINAPI *GetTempPathA_F)(DWORD,LPTSTR);
typedef HANDLE(WINAPI *CreateToolhelp32Snapshot_F)(DWORD,DWORD);
typedef BOOL(WINAPI *Process32First_F)(HANDLE,LPPROCESSENTRY32);
typedef BOOL(WINAPI *Process32Next_F)(HANDLE,LPPROCESSENTRY32);
typedef HANDLE(WINAPI *CreateFileA_F)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);


typedef struct {
	OpenProcess_F OpenProcessF;
	CloseHandle_F CloseHandleF;
	GetTempPathA_F GetTempPathAF;
	CreateToolhelp32Snapshot_F CreateToolhelp32SnapshotF;
	Process32First_F Process32FirstF;
	Process32Next_F Process32NextF;
	CreateFileA_F CreateFileAF;
}Kernel32_API;


typedef BOOL(WINAPI *MiniDumpWriteDump_F)(HANDLE,DWORD,HANDLE,MINIDUMP_TYPE,PMINIDUMP_EXCEPTION_INFORMATION,PMINIDUMP_USER_STREAM_INFORMATION,PMINIDUMP_CALLBACK_INFORMATION);


typedef struct {
	MiniDumpWriteDump_F MiniDumpWriteDumpF;
}Dbghelp_API;



typedef struct {
	Kernel32_API Kernel32Api;
	Dbghelp_API DbghelpApi;
}API_Call;


#ifdef __cplusplus
extern "C" {
#endif
	BOOL loadApi(API_Call *APICall);
#ifdef __cplusplus
}
#endif
