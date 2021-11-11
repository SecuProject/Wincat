#pragma once

typedef HMODULE(WINAPI *LoadLibraryA_F)(LPCTSTR);

typedef BOOL(WINAPI *CloseHandle_F)(HANDLE);
typedef DWORD(WINAPI *GetTempPathA_F)(DWORD, LPTSTR);
typedef DWORD(WINAPI *GetFileAttributesA_F)(LPCSTR);
typedef BOOL(WINAPI *CreateDirectoryA_F)(LPCSTR,LPSECURITY_ATTRIBUTES);
typedef DWORD(WINAPI *GetTempPathA_F)(DWORD,LPSTRlpBuffer);
typedef HANDLE(WINAPI *CreateFileA_F)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL(WINAPI *WriteFile_F)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL(WINAPI *CloseHandle_F)(HANDLE);
typedef BOOL(WINAPI *Wow64DisableWow64FsRedirection_F)(PVOID *);
typedef BOOL(WINAPI *Wow64RevertWow64FsRedirection_F)(PVOID);
typedef void(WINAPI *Sleep_F)(DWORD);


typedef struct {
	CloseHandle_F CloseHandleF;
	GetTempPathA_F GetTempPathAF;
	GetFileAttributesA_F GetFileAttributesAF;
	CreateDirectoryA_F CreateDirectoryAF;
	GetTempPathA_F GetTempPathAF;
	CreateFileA_F CreateFileAF;
	WriteFile_F WriteFileF;
	CloseHandle_F CloseHandleF;
	Wow64DisableWow64FsRedirection_F Wow64DisableWow64FsRedirectionF;
	Wow64RevertWow64FsRedirection_F Wow64RevertWow64FsRedirectionF;
	Sleep_F SleepF;
}Kernel32_API;


typedef HINSTANCE(WINAPI *ShellExecuteA_F)(HWND,LPCSTR,LPCSTR,LPCSTR,LPCSTR,INT);


typedef struct {
	ShellExecuteA_F ShellExecuteAF;
}Shell32_API;


typedef LSTATUS(WINAPI *RegOpenKeyExA_F)(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);
typedef LSTATUS(WINAPI *RegCreateKeyExA_F)(HKEY,LPCSTR,DWORD,LPSTR,DWORD,REGSAM,constLPSECURITY_ATTRIBUTES,PHKEY,LPDWORD);
typedef LSTATUS(WINAPI *RegSetValueExA_F)(HKEY,LPCSTR,DWORD,DWORDdwType,const BYTE*,DWORD);
typedef LSTATUS(WINAPI *RegDeleteTreeA_F)(HKEY,LPCSTR);
typedef LSTATU(WINAPI *RegCloseKey_F)(HKEY);


typedef struct {
	RegOpenKeyExA_F RegOpenKeyExAF;
	RegCreateKeyExA_F RegCreateKeyExAF;
	RegSetValueExA_F RegSetValueExAF;
	RegDeleteTreeA_F RegDeleteTreeAF;
	RegCloseKey_F RegCloseKeyF;
}Advapi32_API;



typedef struct {
	Kernel32_API Kernel32Api;
	Shell32_API Shell32Api;
	Advapi32_API Advapi32Api;
}API_Call;


#ifdef __cplusplus
extern "C" {
#endif
	BOOL loadApi(API_Call *APICall);
#ifdef __cplusplus
}
#endif
